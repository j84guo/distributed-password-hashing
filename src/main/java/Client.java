import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;
import org.mindrot.jbcrypt.BCrypt;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Client {
  public static void main(String[] args) throws Exception {
    if (args.length < 5) {
      System.err.println("Usage: java Client FE_host FE_port logRounds numPasswordsPerRequest numRequestsPerThread <numThreads(defaults to 1)>");
      System.exit(-1);
    }

    int numThreads = -1;
    if (args.length == 6) {
      numThreads = Integer.parseInt(args[5]);

      _threadLocalClient = ThreadLocal.withInitial(() -> {
        TSocket sock = new TSocket(args[0], Integer.parseInt(args[1]));
        TTransport transport = new TFramedTransport(sock);
        TProtocol protocol = new TBinaryProtocol(transport);
        BcryptService.Client client = new BcryptService.Client(protocol);
        try {
          transport.open();
        } catch (TTransportException e) {
          throw new RuntimeException(e);
        }
        return client;
      });
    }

    short logRounds = Short.valueOf(args[2]);
    int numPasswords = Integer.valueOf(args[3]);
    int numRequests = Integer.valueOf(args[4]);

    if (numThreads == -1) {
      correctnessTest(args[0], Integer.parseInt(args[1]), logRounds, numPasswords, numRequests);
    } else {
      performanceTest(args[0], Integer.parseInt(args[1]), logRounds, numPasswords, numRequests, numThreads);
    }
  }

  private static void performanceTest(String host, int port, short logRounds, int numPasswordsPerRequest, int numRequestsPerThread,
                                      int numThreads) {
    ExecutorService pool = Executors.newFixedThreadPool(numThreads);
    Random rand = new Random();
    List<Future<Void>> futures = new ArrayList<>();

    List<String> password = new ArrayList<>();
    for (int j = 0; j < numPasswordsPerRequest; j++) {
      byte[] buf = new byte[1024];
      rand.nextBytes(buf);
      password.add(new String(buf));
    }

    long t1 = System.currentTimeMillis();
    for (int i = 0; i < numThreads; i++) {
      futures.add(pool.submit(() -> {
        try {
          for (int j = 0; j < numRequestsPerThread; j++) {
            _threadLocalClient.get().hashPassword(password, logRounds);
          }
          return null;
        } catch (TException e) {
          throw new RuntimeException(e);
        }
      }));
    }
    for (Future<Void> future : futures) {
      try {
        future.get();
      } catch (InterruptedException | ExecutionException e) {
        throw new RuntimeException(e);
      }
    }
    long t2 = System.currentTimeMillis();
    System.out.println("total time: " + (t2 - t1));

    pool.shutdown();
  }

  private static ThreadLocal<BcryptService.Client> _threadLocalClient;

  private static void correctnessTest(String host, int port, short logRounds, int numPasswords, int numRequests)
      throws TException {
    TSocket sock = new TSocket(host, port);
    TTransport transport = new TFramedTransport(sock);
    TProtocol protocol = new TBinaryProtocol(transport);
    BcryptService.Client client = new BcryptService.Client(protocol);
    transport.open();

    List<String> password = new ArrayList<>();
    Random rand = new Random();
    for (int i = 0; i < numPasswords; i++) {
      byte[] buf = new byte[1024];
      rand.nextBytes(buf);
      password.add(new String(buf));
    }

    for (int i = 0; i < numRequests; i++) {
      long t1 = System.currentTimeMillis();
      List<String> hash = client.hashPassword(password, logRounds);
      long t2 = System.currentTimeMillis();
      System.out.println("latency: " + (t2 - t1));
      List<Boolean> checks1 = checkPasswordLocally(password, hash);
      List<Boolean> checks2 = client.checkPassword(password, hash);
      System.out.println("positive local checks " + checks1);
      System.out.println("positive remote checks " + checks2);
      for (int j = 0; j < hash.size(); j++) {
        hash.set(j, "$2a$14$reBHJvwbb0UWqJHLyPTVF.6Ld5sFRirZx/bXMeMmeurJledKYdZmG");
      }
      System.out.println("negative remote check: " + client.checkPassword(password, hash));
      try {
        for (int j = 0; j < hash.size(); j++) {
          hash.set(j, "bad hash");
        }
        List<Boolean> rets = client.checkPassword(password, hash);
        System.out.println("exception check: no exception thrown");
      } catch (Exception e) {
        e.printStackTrace();
        System.out.println("exception check: exception thrown");
      }
    }

    transport.close();
  }

  private static List<Boolean> checkPasswordLocally(List<String> passwords, List<String> hashes) {
    if (passwords.size() != hashes.size()) {
      throw new IllegalArgumentException("List lengths unequal!");
    }
    List<Boolean> checks = new ArrayList<>();
    for (int i = 0; i < passwords.size(); i++) {
      boolean check;
      try {
        check = BCrypt.checkpw(passwords.get(i), hashes.get(i));
      } catch (Exception e) {
        e.printStackTrace();
        check = false;
      }
      checks.add(check);
    }
    return checks;
  }
}
