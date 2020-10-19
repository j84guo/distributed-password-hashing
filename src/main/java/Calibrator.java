import org.mindrot.jbcrypt.BCrypt;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Calibrator {
  private static void singleThreadedCalibration() {
    int totalNumRounds = 4096;
    for (short l = 8; l <= 12; l++) {
      int numRoundsPerPassword = (int) Math.pow(2, l);
      byte bytes[] = new byte[1024];
      new Random().nextBytes(bytes);
      String password = new String(bytes);

      long startTime = System.currentTimeMillis();
      int numPasswords = totalNumRounds / numRoundsPerPassword;
      System.out.printf(">>> [singleThreadedCalibration] TotalNumRounds=%d NumRoundsPerPassword=%d NumPasswords=%d\n", totalNumRounds, numRoundsPerPassword, numPasswords);
      for (int i = 0; i < numPasswords; i++) {
        BCrypt.hashpw(password, BCrypt.gensalt(l));
      }
      long endTime = System.currentTimeMillis();

      System.out.printf("    Throughput for logRounds=%d: %fpasswords/s\n", l, numPasswords * 1000f / (endTime - startTime));
      System.out.printf("    Latency for logRounds=%d: %fms\n", l, (endTime - startTime) / (double) numPasswords);
      System.out.printf("    Total latency: %dms\n", endTime - startTime);
      System.out.printf("    Latency per round: %fms\n", (endTime - startTime) / 4096f);
    }
  }

  private static void dualThreadedCalibration() throws InterruptedException, ExecutionException {
    int totalNumRounds = 128;
    ExecutorService pool = Executors.newFixedThreadPool(2);
    for (short l = 5; l <= 7; l++) {
      short logNumRoundsPerPassword = l;
      int numRoundsPerPassword = (int) Math.pow(2, logNumRoundsPerPassword);
      byte bytes[] = new byte[1024];
      new Random().nextBytes(bytes);
      String password = new String(bytes);

      long startTime = System.currentTimeMillis();
      int n = totalNumRounds / numRoundsPerPassword;
      System.out.printf(">>> [dualThreadedCalibration] TotalNumRounds=%d NumRoundsPerPassword=%d NumPasswords=%d\n", totalNumRounds, numRoundsPerPassword, n);
      Future<?>[] futures = new Future<?>[n];
      for (int i = 0; i < n; i++) {
        futures[i] = pool.submit(() -> {
          BCrypt.hashpw(password, BCrypt.gensalt(logNumRoundsPerPassword));
        });
      }
      for (Future<?> future : futures) {
        future.get();
      }
      long endTime = System.currentTimeMillis();

      System.out.printf("    Throughput for logRounds=%d: %fpasswords/s\n", logNumRoundsPerPassword, n * 1000f / (endTime - startTime));
      System.out.printf("    Latency for logRounds=%d: %fms\n", logNumRoundsPerPassword, (endTime - startTime) / (double) n);
      System.out.printf("    Total latency: %dms\n", endTime - startTime);
      System.out.printf("    Latency per round: %fms\n", (endTime - startTime) / 4096f);
    }
    pool.shutdownNow();
  }

  public static void main(String[] args) {
    try {
      singleThreadedCalibration();
      System.out.println("----------------------------------------");
      singleThreadedCalibration();
      System.out.println("----------------------------------------");
      singleThreadedCalibration();
      System.out.println("----------------------------------------");
      dualThreadedCalibration();
      System.out.println("----------------------------------------");
      dualThreadedCalibration();
      System.out.println("----------------------------------------");
      dualThreadedCalibration();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
