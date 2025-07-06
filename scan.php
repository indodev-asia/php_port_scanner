<?php
/**
simple php port scanner - code by Anton (www.indodev.asia)
Usage: php scan.php <target_host> <start_port> <end_port> [max_processes]
Example: php scan.php example.com 1 1024 10
**/

function _banner() {
    echo "\n
    \tSimple php port scanner - dev by Anton (www.indodev.asia)
    \n\tUsage: php scan.php <target_host> <start_port> <end_port> [max_processes]
    \n\tExample: php scan.php example.com 1 1024 10
    \n";
}

if (!extension_loaded('pcntl')) {
    echo "Error: The 'pcntl' extension is not loaded. This script requires it for multi-processing.\n";
    echo "Please enable it in your php.ini (e.g., uncomment 'extension=pcntl').\n";
    exit(1);
}

const DEFAULT_MAX_PROCESSES = 5; // Default number of concurrent processes
const CONNECT_TIMEOUT_SECONDS = 1; // Timeout for each port connection attempt

if ($argc < 4 || $argc > 5) {
    _banner();
    exit(1);
}

$targetHost = $argv[1];
$startPort = (int)$argv[2];
$endPort = (int)$argv[3];
$maxProcesses = isset($argv[4]) ? (int)$argv[4] : DEFAULT_MAX_PROCESSES;

if ($startPort < 1 || $endPort > 65535 || $startPort > $endPort) {
    echo "Error: Invalid port range. Ports must be between 1 and 65535, and start_port <= end_port.\n";
    exit(1);
}

if ($maxProcesses < 1) {
    echo "Error: Maximum processes must be at least 1.\n";
    exit(1);
}

echo "Starting port scan on {$targetHost} from port {$startPort} to {$endPort} with {$maxProcesses} concurrent processes...\n\n";

$openPorts = [];
$portsToScan = range($startPort, $endPort);
$totalPorts = count($portsToScan);
$portsPerProcess = ceil($totalPorts / $maxProcesses);

$childPids = [];
$currentPortIndex = 0;

while ($currentPortIndex < $totalPorts || count($childPids) > 0) {
    while (count($childPids) < $maxProcesses && $currentPortIndex < $totalPorts) {
        $pid = pcntl_fork();

        if ($pid == -1) {
            echo "Error: Could not fork process. Exiting.\n";
            exit(1);
        } elseif ($pid == 0) {
            // This is the child process
            $portsForThisProcess = array_slice($portsToScan, $currentPortIndex, $portsPerProcess);
            $foundOpenPorts = [];

            foreach ($portsForThisProcess as $port) {
                $socket = @fsockopen($targetHost, $port, $errno, $errstr, CONNECT_TIMEOUT_SECONDS);

                if ($socket) {
                    fclose($socket);
                    $foundOpenPorts[] = $port;
                    echo "Port {$port} on {$targetHost} is OPEN\n";
                }
            }
            exit(0);
        } else {
            $childPids[$pid] = true;
            $currentPortIndex += $portsPerProcess;
        }
    }

    $status = null;
    $pid = pcntl_waitpid(0, $status, WNOHANG);

    if ($pid > 0) {
        unset($childPids[$pid]);
    } elseif ($pid == 0) {
        usleep(10000); // Sleep for 10 milliseconds
    }
}

echo "\nScan complete.\n";

?>
