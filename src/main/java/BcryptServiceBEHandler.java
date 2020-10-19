import org.apache.log4j.Logger;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class BcryptServiceBEHandler implements BcryptService.Iface {
  @Override
  public List<String> hashPassword(List<String> passwords, short logRounds) {
    List<String> hashes = new ArrayList<>();
    DualThreadedWorker.FuturePair<List<String>> futures = _localWorker.hashPasswords(passwords, logRounds);
    try {
      hashes.addAll(futures.left.get());
      if (futures.right != null) {
        hashes.addAll(futures.right.get());
      }
    } catch (InterruptedException | ExecutionException e) {
      // Our convention is that empty list denotes an error. In practice, we may never check for this since we don't
      // expect the executor to fail.
      return new ArrayList<>();
    }
    return hashes;
  }

  @Override
  public List<Boolean> checkPassword(List<String> passwords, List<String> hashes) {
    List<Boolean> checks = new ArrayList<>();
    DualThreadedWorker.FuturePair<List<Boolean>> futures = _localWorker.checkPasswords(passwords, hashes);
    try {
      checks.addAll(futures.left.get());
      if (futures.right != null) {
        checks.addAll(futures.right.get());
      }
    } catch (InterruptedException | ExecutionException e) {
      return new ArrayList<>();
    }
    return checks;
  }

  private DualThreadedWorker _localWorker = new DualThreadedWorker();

  private static final Logger LOG = Logger.getLogger(BcryptServiceBEHandler.class);
}
