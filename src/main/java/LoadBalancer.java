import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.HashMap;

/**
 * General:
 * Maintain a list of workers (1 FE, 0-4 BE's) and the amount of work each has assigned at the moment
 * (numPasswords * 2^logRounds), which gets increased and decreases as workers get assigned and complete hashing.
 *
 * Simple 1:
 * For each request, choose the least busy worker.
 *
 * Simple 2:
 * For each request, distribute passwords among the available workers (up to 5). This may be simplest in practice.
 *
 * Complex:
 * // singleWorkerTime = numPasswords * 2 ^ (logRounds - 4) * timeFor16Rounds with a default, e.g. 0.136 * 16 = 2.176
 * if (numWorkers == 1 || numPasswords == 1 || singleWorkerTime < 2 * RTT + (1/2) * singleWorkerTime) {
 *   // choose 1 worker (local)
 * } else if (numWorkers == 2 || numPasswords == 2 || singleWorkerTime < 3 * RTT + (1/3) * singleWorkerTime) {
 *   // choose 2 workers
 * } else if (numWorkers == 3 || numPasswords == 3 || singleWorkerTime < 4 * RTT + (1/4) * singleWorkerTime) {
 *   // choose 3 workers
 * } else if (numWorkers == 4 || numPasswords == 4 || singleWorkerTime < 5 * RTT + (1/5) * singleWorkerTime) {
 *   // choose 4 workers
 * } else {
 *   // choose 5 workers
 * }
 *
 * Client Pooling:
 * LoadBalancer only provides the IP and port of the BE (requiring the caller to create and cache their own in thread
 * local storage). A worker thread may end up with an out of date client object for a given BE. The thread will
 * try once to re-connect, but 2 failed attempts mean that the BE is definitely down and an error is reported.
 *
 * Handling BE Failure:
 * An FE thread reports any BE failure, causing the set of client objects for that BE to be invalidated. If 2 FE threads
 * report failure (e.g. they were both performing RPC with the BE, or due to concurrency the second FE thread checks out
 * a BE client before the first FE thread reports a failure), the second report is likely a no-op. In the unlikely case
 * where a BE fails and re-registers in between the first and second failure reports, the second failure report may
 * delete the newly registered BE. A workaround is to map each registration from a particular IP/port combination to an
 * autoincrement integer.
 *
 * Concurrency note:
 * Objects in this class may only be mutated by this class within synchronized methods. The exception is BEClient.async,
 * which may have non-const methods invoked on it by worker threads.
 */
public class LoadBalancer {
  public static abstract class Node implements Comparable<Node> {
    private int load = 0;

    public int getLoad() {
      return load;
    }

    @Override
    public int compareTo(Node node) {
      return load - node.load;
    }
  }

  public static class FENode extends Node {
    private FENode() {}

    @Override
    public String toString() {
      return "<FENode load=" + getLoad() + ">";
    }
  }

  public static class BENode extends Node {
    private BENode(String host, int port, String key, int registrationID) {
      this.host = host;
      this.port = port;
      this.key = key;
      this.registrationID = registrationID;
    }

    @Override
    public String toString() {
      return "<BENode load=" + getLoad() + " host=" + host + " port=" + port + " key=" + key + " registrationID=" + registrationID + ">";
    }

    public final String host;
    public final int port;
    public final String key;
    public final int registrationID;
  }

  // Find the worker with the least cost. Linear scan should be fine since we don't expect more than 4 BE nodes
  private Node chooseLeastNode() {
    Node node1 = _frontendNode;
    for (Node node2 : _activeBackendNodes.values()) {
      if (node2.compareTo(node1) < 0) {
        node1 = node2;
      }
    }
    return node1;
  }

  private static int getCost(int numPasswords, short logRounds) {
    return numPasswords * (int) Math.pow(2, logRounds);
  }

  private List<Node> chooseLeastNodes(int n) {
    ArrayList<Node> allNodes = new ArrayList<>();
    allNodes.add(_frontendNode);
    allNodes.addAll(_activeBackendNodes.values());
    Collections.sort(allNodes);
    return allNodes.subList(0, n);
  }

  public synchronized List<Node> chooseNodes(int numPasswords, short logRounds) {
    // 1. Determine whether 1 or multiple nodes should be used.
    if (numPasswords == 1) {
      Node node = chooseLeastNode();
      node.load += getCost(numPasswords, logRounds);
      return List.of(node);
    } else {
      // 2. Select the number of nodes n [1, 5] to distribute work over.
      int n = Math.min(Math.min(1 + _activeBackendNodes.size(), numPasswords), 5);

      // 3. Find and return the n least busy nodes.
      List<Node> chosen = chooseLeastNodes(n);

      // 4. Increase loads of chosen nodes
      increaseLoads(numPasswords, logRounds, chosen);
      return chosen;
    }
  }

  // Completion causes the worker's load to be decreased by the task cost
  public synchronized void reportSuccess(int numPasswords, short logRounds, List<Node> chosen) {
    decreaseLoads(numPasswords, logRounds, chosen);
  }

  private void increaseLoads(int numPasswords, short logRounds, List<Node> chosen) {
    int u = numPasswords / chosen.size();
    int r = numPasswords % chosen.size();
    for (int i = 0; i < chosen.size(); i++) {
      chosen.get(i).load += getCost(u, logRounds);
      if (i < r) {
        chosen.get(i).load += getCost(1, logRounds);
      }
    }
  }

  private void decreaseLoads(int numPasswords, short logRounds, List<Node> chosen) {
    int u = numPasswords / chosen.size();
    int r = numPasswords % chosen.size();
    for (int i = 0; i < chosen.size(); i++) {
      chosen.get(i).load -= getCost(u, logRounds);
      if (i < r) {
        chosen.get(i).load -= getCost(1, logRounds);
      }
    }
  }

  // Obtain a key and count for a new worker object and add it to the workers set.
  public synchronized void registerBackend(String host, int port) {
    String key = host + " " + port;
    int registrationID = 1;

    Integer oldRegistrationID = _registrationIDs.get(key);
    if (oldRegistrationID != null) {
      registrationID += oldRegistrationID;
    }
    _registrationIDs.put(key, registrationID);

    // May replace existing BE (i.e. BE fails and re-registers before the first failure report)
    BENode newNode = new BENode(host, port, key, registrationID);
    _activeBackendNodes.put(key, newNode);
    LOG.info("registered " + newNode);
    LOG.info("backend nodes " + _activeBackendNodes);
  }

  // A failed node may exist in the node map (first failure report) or it may not exist (multiple failure reports).
  // It may even exist but have a different registrationID (multiple failure reports with re-registration in between).
  public synchronized void reportFailure(int numPasswords, short logRounds, List<Node> chosen,
                                         List<BENode> failedNodes) {
    decreaseLoads(numPasswords, logRounds, chosen);
    for (BENode failedNode : failedNodes) {
      BENode existingNode = _activeBackendNodes.get(failedNode.key);
      if (existingNode != null && failedNode.registrationID == existingNode.registrationID) {
        _activeBackendNodes.remove(failedNode.key);
      }
    }
  }

  // There is always an FE node
  private final FENode _frontendNode = new FENode();

  // We maintain a simple map of BE nodes to search through when a worker thread wants a BE
  private final HashMap<String, BENode> _activeBackendNodes = new HashMap<>();

  // We track the number of times a particular IP-port combination was registered to avoid double failure reports from
  // deleting a re-registered BE (in the scenario that a BE re-registers in between 2 failure reports).
  private final HashMap<String, Integer> _registrationIDs = new HashMap<>();

  private static final Logger LOG = Logger.getLogger(LoadBalancer.class);
}
