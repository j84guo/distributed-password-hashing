import org.mindrot.jbcrypt.BCrypt;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class DualThreadedWorker {
  private static class HashPasswordsCallable implements Callable<List<String>> {
    private HashPasswordsCallable(List<String> passwords, short logRounds, int start, int end) {
      _passwords = passwords;
      _logRounds = logRounds;
      _start = start;
      _end = end;
    }

    @Override
    public List<String> call() {
      List<String> hashes = new ArrayList<>();
      for (int i = _start; i <= _end; i++) {
        hashes.add(BCrypt.hashpw(_passwords.get(i), BCrypt.gensalt(_logRounds)));
      }
      return hashes;
    }

    private final List<String> _passwords;
    private final short _logRounds;
    private final int _start;
    private final int _end;
  }

  private static class CheckPasswordsCallable implements Callable<List<Boolean>> {
    private CheckPasswordsCallable(List<String> passwords, List<String> hashes, int start, int end) {
      _passwords = passwords;
      _hashes = hashes;
      _start = start;
      _end = end;
    }

    @Override
    public List<Boolean> call() {
      List<Boolean> checks = new ArrayList<>();
      for (int i = _start; i <= _end; i++) {
        boolean check;
        try {
          check = BCrypt.checkpw(_passwords.get(i), _hashes.get(i));
        } catch (Exception e) {
          check = false;
        }
        checks.add(check);
      }
      return checks;
    }

    private final List<String> _passwords;
    private final List<String> _hashes;
    private final int _start;
    private final int _end;
  }

  public static class FuturePair<T> {
    public Future<T> left;
    public Future<T> right;
  }

  public FuturePair<List<String>> hashPasswords(List<String> passwords, short logRounds) {
    FuturePair<List<String>> futures = new FuturePair<>();
    int leftStart = 0;
    int leftEnd = (passwords.size() - 1) / 2;
    futures.left = _pool.submit(new HashPasswordsCallable(passwords, logRounds, leftStart, leftEnd));
    if (passwords.size() > 1) {
      int rightStart = leftEnd + 1;
      int rightEnd = passwords.size() - 1;
      futures.right = _pool.submit(new HashPasswordsCallable(passwords, logRounds, rightStart, rightEnd));
    }
    return futures;
  }

  public FuturePair<List<Boolean>> checkPasswords(List<String> passwords, List<String> hashes) {
    FuturePair<List<Boolean>> futures = new FuturePair<>();
    int leftStart = 0;
    int leftEnd = (passwords.size() - 1) / 2;
    futures.left = _pool.submit(new CheckPasswordsCallable(passwords, hashes, leftStart, leftEnd));
    if (passwords.size() > 1) {
      int rightStart = leftEnd + 1;
      int rightEnd = passwords.size() - 1;
      futures.right = _pool.submit(new CheckPasswordsCallable(passwords, hashes, rightStart, rightEnd));
    }
    return futures;
  }

  // For now, we don't have a clean shutdown strategy, we just assume the server runs forever.
  private ExecutorService _pool = Executors.newFixedThreadPool(2);
}
