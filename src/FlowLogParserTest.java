import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

class FlowLogParserTest {

    private Path lookupTableFile;
    private Path protocolMapFile;
    private Path flowLogFile;

    @BeforeEach
    void setUp() throws IOException {
        lookupTableFile = Files.createTempFile("lookup_table", ".csv");
        protocolMapFile = Files.createTempFile("protocol_map", ".csv");
        flowLogFile = Files.createTempFile("flow_log", ".log");

        Files.writeString(lookupTableFile, "dstport,protocol,tag\n" +
                "25,tcp,sv_P1\n" +
                "68,udp,sv_P2\n" +
                "23,tcp,sv_P1\n" +
                "31,udp,sv_P3\n" +
                "443,tcp,sv_P2\n" +
                "22,tcp,sv_P4\n" +
                "3389,tcp,sv_P5\n" +
                "0,icmp,sv_P5\n" +
                "110,tcp,email\n" +
                "993,tcp,email\n" +
                "143,tcp,email\n");

        Files.writeString(protocolMapFile, "6,tcp\n17,udp\n1,icmp\n");

        Files.writeString(flowLogFile, "src1 dst1 1000 srcport1 dstport1 192.168.1.1 25 6\n" +
                "src2 dst2 1000 srcport2 dstport2 192.168.1.2 68 17\n" +
                "src3 dst3 1000 srcport3 dstport3 192.168.1.3 23 6\n" +
                "src4 dst4 1000 srcport4 dstport4 192.168.1.4 31 17\n" +
                "src5 dst5 1000 srcport5 dstport5 192.168.1.5 443 6\n" +
                "src6 dst6 1000 srcport6 dstport6 192.168.1.6 22 6\n" +
                "src7 dst7 1000 srcport7 dstport7 192.168.1.7 3389 6\n" +
                "src8 dst8 1000 srcport8 dstport8 192.168.1.8 0 1\n" +
                "src9 dst9 1000 srcport9 dstport9 192.168.1.9 110 6\n" +
                "src10 dst10 1000 srcport10 dstport10 192.168.1.10 993 6\n" +
                "src11 dst11 1000 srcport11 dstport11 192.168.1.11 143 6\n" +
                "src11 dst11 1000 srcport11 dstport11 192.168.1.11 223 6\n");
    }

    @Test
    void testLoadLookupTable() {
        Map<String, String> lookupTable = FlowLogParser.loadLookupTable(lookupTableFile.toString());

        assertEquals(11, lookupTable.size());
        assertEquals("sv_P1", lookupTable.get("25,tcp"));
        assertEquals("sv_P2", lookupTable.get("68,udp"));
        assertEquals("sv_P4", lookupTable.get("22,tcp"));
        assertEquals("email", lookupTable.get("110,tcp"));
    }

    @Test
    void testLoadProtocolMap() throws IOException {
        Map<Integer, String> protocolMap = FlowLogParser.loadProtocolMap(protocolMapFile.toString());

        assertEquals(3, protocolMap.size());
        assertEquals("tcp", protocolMap.get(6));
        assertEquals("udp", protocolMap.get(17));
        assertEquals("icmp", protocolMap.get(1));
    }

    @Test
    void testProcessLine() {
        Map<String, String> lookupTable = new HashMap<>();
        lookupTable.put("25,tcp", "sv_P1");
        lookupTable.put("68,udp", "sv_P2");
        lookupTable.put("22,tcp", "sv_P4");

        Map<Integer, String> protocolMap = new HashMap<>();
        protocolMap.put(6, "tcp");
        protocolMap.put(17, "udp");
        protocolMap.put(1, "icmp");

        ConcurrentHashMap<String, Integer> tagCounts = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, Integer> portProtocolCounts = new ConcurrentHashMap<>();

        FlowLogParser.processLine("src1 dst1 1000 srcport1 dstport1 192.168.1.1 25 6", lookupTable, protocolMap, tagCounts, portProtocolCounts);

        assertEquals(1, tagCounts.size());
        assertEquals(1, tagCounts.get("sv_P1"));

        assertEquals(1, portProtocolCounts.size());
        assertEquals(1, portProtocolCounts.get("25,tcp"));
    }

    @Test
    void testParseFlowLogConcurrently() throws IOException {
        Map<String, String> lookupTable = FlowLogParser.loadLookupTable(lookupTableFile.toString());
        Map<Integer, String> protocolMap = FlowLogParser.loadProtocolMap(protocolMapFile.toString());

        ConcurrentHashMap<String, Integer> tagCounts = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, Integer> portProtocolCounts = new ConcurrentHashMap<>();

        FlowLogParser.parseFlowLogConcurrently(flowLogFile.toString(), lookupTable, protocolMap, tagCounts, portProtocolCounts);

        assertEquals(7, tagCounts.size());
        assertEquals(2, tagCounts.get("sv_P1"));
        assertEquals(2, tagCounts.get("sv_P2"));
        assertEquals(1, tagCounts.get("sv_P3"));
        assertEquals(1, tagCounts.get("sv_P4"));
        assertEquals(2, tagCounts.get("sv_P5"));
        assertEquals(3, tagCounts.get("email"));
        assertEquals(1, tagCounts.get("Untagged"));

        assertEquals(12, portProtocolCounts.size());
        assertEquals(1, portProtocolCounts.get("25,tcp"));
        assertEquals(1, portProtocolCounts.get("68,udp"));
        assertEquals(1, portProtocolCounts.get("31,udp"));
        assertEquals(1, portProtocolCounts.get("3389,tcp"));
        assertEquals(1, portProtocolCounts.get("0,icmp"));
    }

    @Test
    void testWriteOutput() throws IOException {
        Map<String, Integer> tagCounts = Map.of("sv_P1", 2, "sv_P2", 1, "email", 3);
        Map<String, Integer> portProtocolCounts = Map.of("25,tcp", 1, "68,udp", 1, "110,tcp", 1);

        Path outputFile = Files.createTempFile("output", ".txt");
        FlowLogParser.writeOutput(outputFile.toString(), new ConcurrentHashMap<>(tagCounts), new ConcurrentHashMap<>(portProtocolCounts));

        String content = Files.readString(outputFile);

        assertTrue(content.contains("Tag,Count"));
        assertTrue(content.contains("sv_P1,2"));
        assertTrue(content.contains("email,3"));
        assertTrue(content.contains("Port,Protocol,Count"));
        assertTrue(content.contains("25,tcp,1"));
        assertTrue(content.contains("68,udp,1"));
    }

    @Test
    void testDuplicateFlowLogLines() throws IOException {
        String duplicateLines = "src1 dst1 1000 srcport1 dstport1 192.168.1.1 25 6\n" +
                "src1 dst1 1000 srcport1 dstport1 192.168.1.1 25 6\n" +  // Duplicate line
                "src2 dst2 1000 srcport2 dstport2 192.168.1.2 68 17";

        Files.writeString(flowLogFile, duplicateLines);
        Map<String, String> lookupTable = FlowLogParser.loadLookupTable(lookupTableFile.toString());
        Map<Integer, String> protocolMap = FlowLogParser.loadProtocolMap(protocolMapFile.toString());

        ConcurrentHashMap<String, Integer> tagCounts = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, Integer> portProtocolCounts = new ConcurrentHashMap<>();

        FlowLogParser.parseFlowLogConcurrently(flowLogFile.toString(), lookupTable, protocolMap, tagCounts, portProtocolCounts);

        assertEquals(2, tagCounts.get("sv_P1"));
        assertEquals(1, tagCounts.get("sv_P2"));
        assertEquals(2, portProtocolCounts.get("25,tcp"));
        assertEquals(1, portProtocolCounts.get("68,udp"));
    }

    @Test
    void testMalformedFlowLogLines() throws IOException {
        String malformedLines = "src1 dst1 1000 srcport1 dstport1 192.168.1.1 25 6\n" +
                "incomplete line\n" +  // Too few fields
                "src2 dst2 1000 srcport2 dstport2 192.168.1.2 notAPort 17\n" + // Invalid port
                "src3 dst3 1000 srcport3 dstport3 192.168.1.3 68 notAProtocol\n" + // Invalid protocol
                "src4 dst4 1000 srcport4 dstport4 192.168.1.4 68 17\n" + // Valid line
                "src2 dst2 1000 srcport2 dstport2 192.168.1.2 notAPort -17\n" + // Negative protocol number
                ""; // Empty line

        Files.writeString(flowLogFile, malformedLines);
        Map<String, String> lookupTable = FlowLogParser.loadLookupTable(lookupTableFile.toString());
        Map<Integer, String> protocolMap = FlowLogParser.loadProtocolMap(protocolMapFile.toString());

        ConcurrentHashMap<String, Integer> tagCounts = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, Integer> portProtocolCounts = new ConcurrentHashMap<>();

        assertDoesNotThrow(() -> {
            FlowLogParser.parseFlowLogConcurrently(flowLogFile.toString(), lookupTable, protocolMap, tagCounts, portProtocolCounts);
        });

        assertEquals(3, tagCounts.size());
        assertEquals(2, tagCounts.get("Untagged"));
        assertEquals(1, tagCounts.get("sv_P1"));
        assertEquals(1, tagCounts.get("sv_P2"));
    }

    @Test
    void testEmptyFlowLogFile() throws IOException {
        Files.writeString(flowLogFile, "");
        Map<String, String> lookupTable = FlowLogParser.loadLookupTable(lookupTableFile.toString());
        Map<Integer, String> protocolMap = FlowLogParser.loadProtocolMap(protocolMapFile.toString());

        ConcurrentHashMap<String, Integer> tagCounts = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, Integer> portProtocolCounts = new ConcurrentHashMap<>();

        FlowLogParser.parseFlowLogConcurrently(flowLogFile.toString(), lookupTable, protocolMap, tagCounts, portProtocolCounts);

        assertTrue(tagCounts.isEmpty());
        assertTrue(portProtocolCounts.isEmpty());
    }

    @Test
    void testConcurrentAccess() throws IOException {
        StringBuilder largeLog = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            largeLog.append("src1 dst1 1000 srcport1 dstport1 192.168.1.1 25 6\n");
        }
        Files.writeString(flowLogFile, largeLog.toString());
        Map<String, String> lookupTable = FlowLogParser.loadLookupTable(lookupTableFile.toString());
        Map<Integer, String> protocolMap = FlowLogParser.loadProtocolMap(protocolMapFile.toString());

        ConcurrentHashMap<String, Integer> tagCounts = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, Integer> portProtocolCounts = new ConcurrentHashMap<>();

        FlowLogParser.parseFlowLogConcurrently(flowLogFile.toString(), lookupTable, protocolMap, tagCounts, portProtocolCounts);

        assertEquals(1000, tagCounts.get("sv_P1"));
        assertEquals(1000, portProtocolCounts.get("25,tcp"));
    }

    @Test
    void testLargeFileProcessing() throws IOException {
        // Create large lookup table (10000 entries)
        StringBuilder largeLookupTable = new StringBuilder("dstport,protocol,tag\n");
        for (int i = 1; i <= 10000; i++) {
            largeLookupTable.append(i).append(",tcp,service_").append(i).append("\n");
            if (i % 2 == 0) {
                largeLookupTable.append(i).append(",udp,service_").append(i).append("_udp\n");
            }
        }
        Files.writeString(lookupTableFile, largeLookupTable.toString());
        Map<String, String> lookupTable = FlowLogParser.loadLookupTable(lookupTableFile.toString());
        Map<Integer, String> protocolMap = FlowLogParser.loadProtocolMap(protocolMapFile.toString());

        StringBuilder largeFlowLog = new StringBuilder();
        int numberOfLines = 100000; // Approximately 10MB
        Map<String, Integer> expectedTagCounts = new HashMap<>();
        Map<String, Integer> expectedPortProtocolCounts = new HashMap<>();

        for (int i = 0; i < numberOfLines; i++) {
            int port = (i % 10000) + 1; // Cycle through ports 1-10000
            boolean useTcp = i % 2 == 0; // Alternate between TCP and UDP
            int protocol = useTcp ? 6 : 17;

            String line = String.format("src%d dst%d 1000 srcport%d dstport%d 192.168.1.%d %d %d\n",
                    i, i, i, i, (i % 255) + 1, port, protocol);
            largeFlowLog.append(line);

            String portProtocolKey = port + "," + (useTcp ? "tcp" : "udp");
            expectedPortProtocolCounts.merge(portProtocolKey, 1, Integer::sum);
            String tag = lookupTable.get(portProtocolKey);
            expectedTagCounts.merge(tag, 1, Integer::sum);
        }
        Files.writeString(flowLogFile, largeFlowLog.toString());

        ConcurrentHashMap<String, Integer> tagCounts = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, Integer> portProtocolCounts = new ConcurrentHashMap<>();

        // Measure performance
        long startTime = System.currentTimeMillis();
        FlowLogParser.parseFlowLogConcurrently(flowLogFile.toString(), lookupTable, protocolMap, tagCounts, portProtocolCounts);
        long processingTime = System.currentTimeMillis() - startTime;
        System.out.println("Processing time large flow log files " + processingTime + " ms");

        assertEquals(expectedTagCounts.size(), tagCounts.size(),
                "Tag counts size mismatch");
        assertEquals(expectedPortProtocolCounts.size(), portProtocolCounts.size(),
                "Port/Protocol counts size mismatch");

        expectedTagCounts.forEach((tag, count) ->
                assertEquals(count, tagCounts.get(tag),
                        "Mismatch for tag: " + tag));

        expectedPortProtocolCounts.forEach((key, count) ->
                assertEquals(count, portProtocolCounts.get(key),
                        "Mismatch for port/protocol: " + key));

    }
}

