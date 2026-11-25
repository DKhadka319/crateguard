import org.neo4j.dbms.api.*; import org.neo4j.configuration.*; import org.neo4j.configuration.connectors.*; import org.neo4j.configuration.helpers.SocketAddress; import java.nio.file.Path;
public class Server { public static void main(String[] a) throws Exception {
 DatabaseManagementService m = new DatabaseManagementServiceBuilder(Path.of(a[0]))
  .setConfig(BoltConnector.enabled, true).setConfig(BoltConnector.listen_address, new SocketAddress("localhost",7687))
  .setConfig(GraphDatabaseSettings.auth_enabled, false)
  .setConfig(GraphDatabaseSettings.load_csv_file_url_root, Path.of(a[1])).build();
 System.out.println("READY"); Runtime.getRuntime().addShutdownHook(new Thread(m::shutdown)); Thread.currentThread().join(); } }
