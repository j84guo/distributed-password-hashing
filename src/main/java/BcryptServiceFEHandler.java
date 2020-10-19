import org.apache.log4j.Logger;
import org.apache.thrift.TApplicationException;
import org.apache.thrift.TException;
import org.apache.thrift.async.AsyncMethodCallback;
import org.apache.thrift.async.TAsyncClientManager;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TNonblockingSocket;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;

public class BcryptServiceFEHandler implements BcryptServiceFE.Iface {
  public BcryptServiceFEHandler() throws IOException {
    _manager = new TAsyncClientManager();
  }

  private void checkLogRoundsInRange(short logRounds) throws IllegalArgument {
    if (logRounds < 4 || logRounds > 30) {
      throw new IllegalArgument("logRounds must be within [4, 30].");
    }
  }

  private void checkListNonEmpty(List<String> l) throws IllegalArgument {
    if (l.size() == 0) {
      throw new IllegalArgument("List must be non-empty.");
    }
  }

  private void checkPasswordsHashesLength(List<String> passwords, List<String> hashes) throws IllegalArgument {
    if (passwords.size() != hashes.size()) {
      throw new IllegalArgument("Passwords and hashes lists must have equal length.");
    }
  }

  // This may catch out of date clients, but it is not guaranteed! Therefore we must also check for
  // IllegalStateException when using clients.
  private void ensureClientsExist(List<LoadBalancer.Node> chosen) throws IOException {
    HashMap<String, BEAsyncClient> clients = _threadLocalClients.get();
    for (LoadBalancer.Node node : chosen) {
      if (node instanceof LoadBalancer.FENode) {
        continue;
      }
      LoadBalancer.BENode chosenBENode = (LoadBalancer.BENode) node;
      BEAsyncClient existingClient = clients.get(chosenBENode.key);
      if (existingClient == null || existingClient._node.registrationID < chosenBENode.registrationID) {
        if (existingClient != null && existingClient._socket.isOpen()) {
          existingClient._socket.close();
        }
        clients.put(chosenBENode.key, new BEAsyncClient(_manager, chosenBENode));
      }
    }
  }

  @Override
  public List<String> hashPassword(List<String> passwords, short logRounds) throws TException {
    checkListNonEmpty(passwords);
    checkLogRoundsInRange(logRounds);
    List<String> hashes;
    do {
      try {
        hashes = tryHashPasswordDistributed(passwords, logRounds);
      } catch (IOException | InterruptedException | ExecutionException e) {
        throw new TApplicationException(e.getMessage());
      }
    } while (hashes == null);
    return hashes;
  }

  private static int[] partition(int numChosen, int numPasswords) {
    int[] partitions = new int[numChosen];
    int u = numPasswords / numChosen;
    int r = numPasswords % numChosen;
    for (int i = 0; i < partitions.length; i++) {
      partitions[i] = u;
      if (i < r) {
        partitions[i]++;
      }
    }
    return partitions;
  }

  private int countBENodes(List<LoadBalancer.Node> chosen) {
    int numBENodes = 0;
    for (LoadBalancer.Node node : chosen) {
      if (node instanceof LoadBalancer.BENode) {
        numBENodes++;
      }
    }
    return numBENodes;
  }

  private static <T> List<T> collectLocalResults(DualThreadedWorker.FuturePair<List<T>> futures)
      throws InterruptedException, ExecutionException {
    List<T> result = new ArrayList<>();
    result.addAll(futures.left.get());
    if (futures.right != null) {
      result.addAll(futures.right.get());
    }
    return result;
  }

  // This assumes results contains lists of type T. ClassCastException arises if it is not!
  private static <T> List<T> collectAllResults(List results[]) {
    List<T> combined = new ArrayList<>();
    for (List result : results) { 
      combined.addAll(result);
    }
    return combined;
  }

  private void handleBENodeFailures(int numPasswords, short logRounds, List<LoadBalancer.Node> chosen,
                                    List<LoadBalancer.BENode> failedNodes) {
    _loadBalancer.reportFailure(numPasswords, logRounds, chosen, failedNodes);
    HashMap<String, BEAsyncClient> clients = _threadLocalClients.get();
    for (LoadBalancer.BENode failedNode : failedNodes) {
      clients.get(failedNode.key)._socket.close();
    }
  }

  // If error on remote BE, re-try (return null). If error on local FE, exception.
  private List<String> tryHashPasswordDistributed(List<String> passwords, short logRounds) throws TException,
      InterruptedException, ExecutionException, IOException {
    // Choose worker nodes
    List<LoadBalancer.Node> chosen = _loadBalancer.chooseNodes(passwords.size(), logRounds);

    // Ensure necessary clients exist. Failure to create one (e.g. too many socket descriptors) results in exception.
    ensureClientsExist(chosen);

    // Prepare to launch async work
    DualThreadedWorker.FuturePair<List<String>> futures = null;
    CountDownLatch latch = null;
    List<LoadBalancer.BENode> failedNodes = new ArrayList<>();
    int numBENodes = countBENodes(chosen);
    if (numBENodes > 0) {
      latch = new CountDownLatch(numBENodes);
    }

    // Launch async work
    int[] partitions = partition(chosen.size(), passwords.size());
    LOG.info("chosen " + chosen);
    LOG.info("partitions " + Arrays.toString(partitions));

    List results[] = new List[chosen.size()];
    int passwordIdx = 0;
    int partitionIdx = 0;
    int localPartitionIdx = -1;

    HashMap<String, BEAsyncClient> clients = _threadLocalClients.get();
    for (LoadBalancer.Node node : chosen) {
      List<String> partition = passwords.subList(passwordIdx, passwordIdx + partitions[partitionIdx]);
      if (node instanceof LoadBalancer.FENode) {
        futures = _localWorker.hashPasswords(partition, logRounds);
        localPartitionIdx = partitionIdx;
      } else if (node instanceof LoadBalancer.BENode) {
        LoadBalancer.BENode beNode = (LoadBalancer.BENode) node;
        try {
          BENodeCallback<String> callback = new BENodeCallback<>(results, partitionIdx, latch, beNode, failedNodes);
          clients.get(beNode.key)._async.hashPassword(partition, logRounds, callback);
        } catch (IllegalStateException e) {
          failedNodes.add(beNode);
          latch.countDown();
        }
      }
      passwordIdx += partitions[partitionIdx];
      partitionIdx++;
    }

    // Wait on any local work
    if (futures != null) {
      results[localPartitionIdx] = collectLocalResults(futures);
    }

    // Wait on any remote work
    if (latch != null) {
      latch.await();
      if (failedNodes.size() > 0) {
        handleBENodeFailures(passwords.size(), logRounds, chosen, failedNodes);
        return null;
      }
    }

    _loadBalancer.reportSuccess(passwords.size(), logRounds, chosen);
    return collectAllResults(results);
  }

  private static class BENodeCallback<T> implements AsyncMethodCallback<List<T>> {
    private BENodeCallback(List[] results, int resultIdx, CountDownLatch latch, LoadBalancer.BENode node,
                           List<LoadBalancer.BENode> failedNodes) {
      _results = results;
      _resultIdx = resultIdx;
      _latch = latch;
      _node = node;
      _failedNodes = failedNodes;
    }

    @Override
    public void onComplete(List<T> result) {
      _results[_resultIdx] = result;
      _latch.countDown();
    }

    @Override
    public void onError(Exception e) {
      e.printStackTrace();
      synchronized (_failedNodes) {
        _failedNodes.add(_node);
      }
      _latch.countDown();
    }

    private List[] _results;
    private int _resultIdx;
    private CountDownLatch _latch;
    private LoadBalancer.BENode _node;
    private List<LoadBalancer.BENode> _failedNodes;
  }

  @Override
  public List<Boolean> checkPassword(List<String> passwords, List<String> hashes) throws TException {
    checkListNonEmpty(passwords);
    checkListNonEmpty(hashes);
    checkPasswordsHashesLength(passwords, hashes);

    List<Boolean> checks;
    do {
      try {
        checks = tryCheckPasswordDistributed(passwords, hashes);
      } catch (IOException | InterruptedException | ExecutionException e) {
        throw new TApplicationException(e.getMessage());
      }
    } while (checks == null);
    return checks;
  }

  private List<Boolean> tryCheckPasswordDistributed(List<String> passwords, List<String> hashes) throws IOException,
      InterruptedException, ExecutionException, TException {
    // We hardcode logRounds even though this may not be the case
    final short logRounds = 0;

    // Choose worker nodes
    List<LoadBalancer.Node> chosen = _loadBalancer.chooseNodes(passwords.size(), logRounds);

    // Ensure necessary clients exist. Failure to create one (e.g. too many socket descriptors) results in exception.
    ensureClientsExist(chosen);

    // Prepare to launch async work
    DualThreadedWorker.FuturePair<List<Boolean>> futures = null;
    CountDownLatch latch = null;
    List<LoadBalancer.BENode> failedNodes = new ArrayList<>();
    int numBENodes = countBENodes(chosen);
    if (numBENodes > 0) {
      latch = new CountDownLatch(numBENodes);
    }

    // Launch async work
    int[] partitions = partition(chosen.size(), passwords.size());
    LOG.info("chosen " + chosen);
    LOG.info("partitions " + Arrays.toString(partitions));

    List results[] = new List[chosen.size()];
    int passwordIdx = 0;
    int partitionIdx = 0;
    int localPartitionIdx = -1;

    HashMap<String, BEAsyncClient> clients = _threadLocalClients.get();
    for (LoadBalancer.Node node : chosen) {
      List<String> passwordsPartition = passwords.subList(passwordIdx, passwordIdx + partitions[partitionIdx]);
      List<String> hashesPartition = hashes.subList(passwordIdx, passwordIdx + partitions[partitionIdx]);
      if (node instanceof LoadBalancer.FENode) {
        futures = _localWorker.checkPasswords(passwordsPartition, hashesPartition);
        localPartitionIdx = partitionIdx;
      } else if (node instanceof LoadBalancer.BENode) {
        LoadBalancer.BENode beNode = (LoadBalancer.BENode) node;
        try {
          BENodeCallback<Boolean> callback = new BENodeCallback<>(results, partitionIdx, latch, beNode, failedNodes);
          clients.get(beNode.key)._async.checkPassword(passwordsPartition, hashesPartition, callback);
        } catch (IllegalStateException e) {
          failedNodes.add(beNode);
          latch.countDown();
        }
      }
      passwordIdx += partitions[partitionIdx];
      partitionIdx++;
    }

    // Wait on any local work
    if (futures != null) {
      results[localPartitionIdx] = collectLocalResults(futures);
    }

    // Wait on any remote work
    if (latch != null) {
      latch.await();
      if (failedNodes.size() > 0) {
        handleBENodeFailures(passwords.size(), logRounds, chosen, failedNodes);
        return null;
      }
    }

    _loadBalancer.reportSuccess(passwords.size(), logRounds, chosen);
    return collectAllResults(results);
  }

  @Override
  public void registerBackend(String host, int port) {
    _loadBalancer.registerBackend(host, port);
  }

  // Since this object will be shared by all server threads, we instantiate the load balancer and thread pool as
  // instance variables.
  private LoadBalancer _loadBalancer = new LoadBalancer();
  private DualThreadedWorker _localWorker = new DualThreadedWorker();

  // The client is associated with a BENode so that the worker thread can determine whether the client is in a valid
  // state by checking the registration count of the BENode matches that of the cached client (identity equality would
  // also work).
  private static class BEAsyncClient {
    private BEAsyncClient(TAsyncClientManager manager, LoadBalancer.BENode node) throws IOException {
      _socket = new TNonblockingSocket(node.host, node.port);
      _async = new BcryptService.AsyncClient(new TBinaryProtocol.Factory(), manager, _socket);
      _node = node;
    }

    private TNonblockingSocket _socket;
    private BcryptService.AsyncClient _async;
    private LoadBalancer.BENode _node;
  }

  // Currently, the manager is shared by all clients
  private static TAsyncClientManager _manager;

  // However each thread needs to maintain its own ThreadLocal cache of clients.
  private static final ThreadLocal<HashMap<String, BEAsyncClient>> _threadLocalClients =
      ThreadLocal.withInitial(() -> new HashMap<>());

  private static final Logger LOG = Logger.getLogger(BcryptServiceFEHandler.class);
}
