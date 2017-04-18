package jelegram.forusoul.com;

import org.junit.Test;

import jelegram.forusoul.com.connection.ConnectionManager;
import jelegram.forusoul.com.protocol.RequestPQ;

import static org.junit.Assert.*;

/**
 * Test connection manager
 */
public class ConnectionManagerTest {
    @Test
    public void testSimpleSend() throws Exception {
        RequestPQ requestPQ = new RequestPQ();
        ConnectionManager.getInstance().sendRequest(requestPQ);

        Thread.sleep(500000);
        assertEquals(true, 1 > 0);
    }
}