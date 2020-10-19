import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.apache.thrift.TException;
import org.apache.thrift.TProcessor;
import org.apache.thrift.TProcessorFactory;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.server.TThreadPoolServer;
import org.apache.thrift.transport.*;

import java.net.InetAddress;
import java.net.UnknownHostException;

public class BENode {
  public static void main(String[] args) throws Exception {
    if (args.length != 3) {
      System.err.println("Usage: java BENode FE_host FE_port BE_port");
      System.exit(-1);
    }

    // Initialize log4j
    BasicConfigurator.configure();

    // Get input arguments
    String hostFE = args[0];
    int portFE = Integer.parseInt(args[1]);
    int portBE = Integer.parseInt(args[2]);
    LOG.info("Launching BE node on port " + portBE + " at host " + getHostName());

    // Prepare Thrift server
    TProcessor processor = new BcryptService.Processor<>(new BcryptServiceBEHandler());
    TServerSocket socket = new TServerSocket(portBE);
    TThreadPoolServer.Args serverArgs = new TThreadPoolServer.Args(socket)
        .protocolFactory(new TBinaryProtocol.Factory())
        .transportFactory(new TFramedTransport.Factory())
        .processorFactory(new TProcessorFactory(processor))
        .minWorkerThreads(20)
        .maxWorkerThreads(Integer.MAX_VALUE); // Apparently TAsyncClient hangs if a connection is rejected, so we allow unlimited connections here
    TThreadPoolServer server = new TThreadPoolServer(serverArgs);

    // Launch FE registration thread
    launchFERegistrationThread(hostFE, portFE, portBE);

    // Launch Thrift server
    server.serve();
  }

  private static void launchFERegistrationThread(String hostFE, int portFE, int portBE) {
    Thread registrationThread = new Thread(() -> {
      int numAttempts = 1;
      while (true) {
        try {
          Thread.sleep(250);
        } catch (InterruptedException e) {
          break;
        }
        TSocket socket = new TSocket(hostFE, portFE);
        TTransport transport = new TFramedTransport(socket);
        TProtocol protocol = new TBinaryProtocol(transport);
        BcryptServiceFE.Client client = new BcryptServiceFE.Client(protocol);
        try {
          transport.open();
          try {
            client.registerBackend(getHostName(), portBE);
            LOG.info("FE connection established with " + socket.getSocket().getInetAddress());
            break;
          } finally {
            transport.close();
          }
        } catch (TException e) {
          LOG.info("FE connection attempt " + numAttempts + " failed with error " + e.getMessage());
          numAttempts++;
        }
      }
    });
    registrationThread.setDaemon(true);
    registrationThread.start();
  }

  private static String getHostName() {
    try {
      return InetAddress.getLocalHost().getHostName();
    } catch (UnknownHostException e) {
      return "localhost";
    }
  }

  private static final Logger LOG = Logger.getLogger(BENode.class);
}
