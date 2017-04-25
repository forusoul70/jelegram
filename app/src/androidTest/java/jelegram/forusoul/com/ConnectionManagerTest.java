package jelegram.forusoul.com;

import org.junit.Test;

import jelegram.forusoul.com.connection.ConnectionManager;

import static org.junit.Assert.assertEquals;

/**
 * Test connection manager
 */
public class ConnectionManagerTest {
    @Test
    public void testSimpleSend() throws Exception {

        ConnectionManager.getInstance();

        Thread.sleep(500000);
        assertEquals(true, 1 > 0);
    }
}