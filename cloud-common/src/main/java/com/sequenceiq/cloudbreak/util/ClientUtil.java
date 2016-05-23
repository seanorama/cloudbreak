package com.sequenceiq.cloudbreak.util;

import static org.terracotta.modules.ehcache.store.TerracottaClusteredInstanceFactory.LOGGER;

import javax.net.ssl.SSLContext;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;

import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;
import org.glassfish.jersey.apache.connector.ApacheClientProperties;
import org.glassfish.jersey.apache.connector.ApacheConnectorProvider;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.ClientProperties;
import org.glassfish.jersey.client.JerseyClientBuilder;
import org.glassfish.jersey.client.authentication.HttpAuthenticationFeature;
import org.glassfish.jersey.filter.LoggingFilter;

public class ClientUtil {

    private static final String USER = "cbadmin";
    private static final String PASSWORD = "cbadmin";

    // apache http connection pool defaults are constraining
    // https://hc.apache.org/httpcomponents-client-ga/tutorial/html/connmgmt.html
    private static final int MAX_TOTAL_CONNECTION = 100;
    private static final int MAX_PER_ROUTE_CONNECTION = 20;

    private ClientUtil() {
    }

    public static Client createClient(String serverCert, String clientCert, String clientKey) throws Exception {
        return createClient(serverCert, clientCert, clientKey, false, null);
    }

    public static Client createClient(String serverCert, String clientCert, String clientKey, boolean debug, Class debugClass) throws Exception {

        SSLContext sslContext = SSLContexts.custom()
                .loadTrustMaterial(KeyStoreUtil.createTrustStore(serverCert), null)
                .loadKeyMaterial(KeyStoreUtil.createKeyStore(clientCert, clientKey), "consul".toCharArray())
                .build();

        LOGGER.info("Constructing jax rs client for config: server cert: {}, client cert: {}, debug: {}", serverCert, clientCert, debug);
        ClientConfig config = new ClientConfig();
        config.property(ClientProperties.FOLLOW_REDIRECTS, "false");

        RegistryBuilder<ConnectionSocketFactory> registryBuilder = RegistryBuilder.create();
        registryBuilder.register("http", PlainConnectionSocketFactory.getSocketFactory());
        registryBuilder.register("https", new SSLConnectionSocketFactory(sslContext));

        PoolingHttpClientConnectionManager connectionManager =
                new PoolingHttpClientConnectionManager(registryBuilder.build());

        connectionManager.setMaxTotal(MAX_TOTAL_CONNECTION);
        connectionManager.setDefaultMaxPerRoute(MAX_PER_ROUTE_CONNECTION);

        // tell the jersey config about the connection manager
        config.property(ApacheClientProperties.CONNECTION_MANAGER, connectionManager);
        config.connectorProvider(new ApacheConnectorProvider());

        ClientBuilder builder = JerseyClientBuilder.newBuilder().withConfig(config);

        if (debug) {
            builder = builder.register(new LoggingFilter(java.util.logging.Logger.getLogger(debugClass.getName()),
                    true));
        }

        Client client = builder.build();
        LOGGER.info("Jax rs client has been constructed: {}, sslContext: {}", client, sslContext);
        return client;
    }

    public static WebTarget createTarget(Client client, String address) {
        HttpAuthenticationFeature feature = HttpAuthenticationFeature.basic(USER, PASSWORD);
        return client.target(address).register(feature);
    }
}
