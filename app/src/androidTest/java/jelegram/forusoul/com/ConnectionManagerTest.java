package jelegram.forusoul.com;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Test connection manager
 */
public class ConnectionManagerTest {
    @Test
    public void testSimpleSend() {
        String testString = "Hello";
        ConnectionManager.getInstance().sendRequest(testString.getBytes());
        assertEquals(true, testString.length() > 0);
    }
}