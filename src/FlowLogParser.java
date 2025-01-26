import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class FlowLogParser {

    private static final Map<Integer, String> PROTOCOL_MAP = Map.of(
            1, "icmp",
            6, "tcp",
            17, "udp",
            47, "gre",
            50, "esp",
            51, "ah",
            89, "ospf",
            132, "sctp"
    );

    public static void main(String[] args) {
        if (args.length < 3 || args.length > 4) {
            System.out.println("Usage: java FlowLogParser <flow_log_file> <lookup_table_file> <output_file> [protocol_map_file]");
            return;
        }

        String flowLogFile = args[0];
        String lookupTableFile = args[1];
        String outputFile = args[2];
        String protocolMapFile = args.length == 4 ? args[3] : null;

        Map<String, String> lookupTable = loadLookupTable(lookupTableFile);
        Map<Integer, String> protocolMap = protocolMapFile != null ? loadProtocolMap(protocolMapFile) : PROTOCOL_MAP;
        ConcurrentHashMap<String, Integer> tagCounts = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, Integer> portProtocolCounts = new ConcurrentHashMap<>();

        parseFlowLogConcurrently(flowLogFile, lookupTable, protocolMap, tagCounts, portProtocolCounts);
        writeOutput(outputFile, tagCounts, portProtocolCounts);
        System.out.println("Output is written to file : " + outputFile);
    }

    static Map<String, String> loadLookupTable(String lookupTableFile) {
        Map<String, String> lookupTable = new HashMap<>();
        try (BufferedReader br = new BufferedReader(new FileReader(lookupTableFile))) {
            String line;
            boolean firstLine = true;
            while ((line = br.readLine()) != null) {
                if (firstLine) {
                    firstLine = false;
                    continue;
                }
                String[] values = line.split(",");
                if (values.length == 3) {
                    String dstPort = values[0].trim().toLowerCase();
                    String protocol = values[1].trim().toLowerCase();
                    String tag = values[2].trim();
                    String key = dstPort + "," + protocol;
                    lookupTable.put(key, tag);
                }
            }
        } catch (IOException e) {
            System.err.println("Error loading lookup table: " + e.getMessage());
            throw new RuntimeException(e);
        }
        return lookupTable;
    }

    static Map<Integer, String> loadProtocolMap(String protocolMapFile) {
        Map<Integer, String> protocolMap = new HashMap<>();
        try (BufferedReader br = new BufferedReader(new FileReader(protocolMapFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] values = line.split(",");
                if (values.length == 2) {
                    int protocolNumber = Integer.parseInt(values[0].trim());
                    String protocolName = values[1].trim().toLowerCase();
                    protocolMap.put(protocolNumber, protocolName);
                }
            }
        } catch (IOException e) {
            System.err.println("Error loading protocol map: " + e.getMessage());
            throw new RuntimeException(e);
        }
        return protocolMap;
    }

    static void parseFlowLogConcurrently(String flowLogFile, Map<String, String> lookupTable,
                                         Map<Integer, String> protocolMap,
                                         ConcurrentHashMap<String, Integer> tagCounts,
                                         ConcurrentHashMap<String, Integer> portProtocolCounts) {
        int numberOfThreads = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(numberOfThreads);

        try (BufferedReader br = new BufferedReader(new FileReader(flowLogFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                String finalLine = line;
                executor.submit(() -> processLine(finalLine, lookupTable, protocolMap, tagCounts, portProtocolCounts));
            }
        } catch (IOException e) {
            System.err.println("Error reading flow log file: " + e.getMessage());
            throw new RuntimeException(e);
        }

        executor.shutdown();
        try {
            if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException ex) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
            System.err.println("Error awaiting termination of executor: " + ex.getMessage());
            throw new RuntimeException(ex);
        }
    }

    static void processLine(String line, Map<String, String> lookupTable,
                            Map<Integer, String> protocolMap,
                            ConcurrentHashMap<String, Integer> tagCounts,
                            ConcurrentHashMap<String, Integer> portProtocolCounts) {
        String[] fields = line.split(" ");
        if (fields.length >= 8) {
            String dstPort = fields[6].toLowerCase();
            int protocolNumber;
            try {
                protocolNumber = Integer.parseInt(fields[7]);
            } catch (NumberFormatException ex) {
                return; //skip invalid protocol numbers
            }
            String protocol = protocolMap.getOrDefault(protocolNumber, "UNKNOWN").toLowerCase();
            String key = dstPort + "," + protocol;
            String tag = lookupTable.getOrDefault(key, "Untagged");

            tagCounts.merge(tag, 1, Integer::sum);
            portProtocolCounts.merge(key, 1, Integer::sum);
        }
    }

    static void writeOutput(String outputFile, ConcurrentHashMap<String, Integer> tagCounts,
                            ConcurrentHashMap<String, Integer> portProtocolCounts) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
            writer.println("Tag Counts:");
            writer.println("Tag,Count");
            for (Map.Entry<String, Integer> entry : tagCounts.entrySet()) {
                writer.println(entry.getKey() + "," + entry.getValue());
            }

            writer.println("\nPort/Protocol Combination Counts:");
            writer.println("Port,Protocol,Count");
            for (Map.Entry<String, Integer> entry : portProtocolCounts.entrySet()) {
                String[] keyParts = entry.getKey().split(",");
                if (keyParts.length == 2) {
                    writer.println(keyParts[0] + "," + keyParts[1] + "," + entry.getValue());
                }
            }
        } catch (IOException e) {
            System.err.println("Error writing output file: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }
}
