import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;
import org.apache.thrift.TProcessor;
import org.apache.thrift.TProcessorFactory;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.server.TThreadPoolServer;
import org.apache.thrift.transport.TFramedTransport;
import org.apache.thrift.transport.TServerSocket;

public class FENode {
  public static void main(String[] args) throws Exception {
    if (args.length != 1) {
      System.err.println("Usage: java FENode FE_port");
      System.exit(-1);
    }

    // Initialize log4j
    BasicConfigurator.configure();

    // Get port
    int FEPort = Integer.parseInt(args[0]);
    LOG.info("Launching FE node on port " + FEPort);

    // Launch Thrift server
    TServerSocket serverSocket = new TServerSocket(FEPort);
    TProcessor processor = new BcryptServiceFE.Processor<>(new BcryptServiceFEHandler());
    TThreadPoolServer.Args serverArgs = new TThreadPoolServer.Args(serverSocket)
        .protocolFactory(new TBinaryProtocol.Factory())
        .transportFactory(new TFramedTransport.Factory())
        .processorFactory(new TProcessorFactory(processor))
        .minWorkerThreads(20)
        .maxWorkerThreads(64);
    TThreadPoolServer server = new TThreadPoolServer(serverArgs);
    server.serve();
  }

  private static final Logger LOG = Logger.getLogger(FENode.class);
}
