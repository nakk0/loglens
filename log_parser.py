# log_parser.py - Parses log files into structured data

import re
import datetime
import csv
import os

class LogEntry:
    def __init__(self, timestamp, severity, source, message):
        self.timestamp = timestamp
        self.severity = severity
        self.source = source
        self.message = message
    
    def __str__(self):
        return f"[{self.timestamp}] {self.severity} - {self.source}: {self.message}"

class LogParser:
    def __init__(self):
        # Regular expressions for common log formats
        self.patterns = {
            'standard': re.compile(r'^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (\w+) - ([^:]+): (.+)$'),
            'apache': re.compile(r'^(\S+) \S+ \S+ \[([^]]+)\] "([^"]+)" (\d+) (\d+) "([^"]*)" "([^"]*)"$'),
            'syslog': re.compile(r'^(\w{3} \d{2} \d{2}:\d{2}:\d{2}) (\S+) ([^:]+): (.+)$')
        }
    
    def _detect_format(self, line):
        """Detect the format of a log line"""
        for format_name, pattern in self.patterns.items():
            if pattern.match(line):
                return format_name
        return None
    
    def parse_file(self, file_path):
        """Parse a log file and return a list of LogEntry objects"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        log_entries = []
        detected_format = None
        
        with open(file_path, 'r') as f:
            # Try to detect format from first line
            first_line = f.readline().strip()
            detected_format = self._detect_format(first_line)
            f.seek(0)  # Reset to file beginning
            
            if detected_format == 'standard':
                for line in f:
                    entry = self._parse_standard_format(line)
                    if entry:
                        log_entries.append(entry)
            elif detected_format == 'apache':
                for line in f:
                    entry = self._parse_apache_format(line)
                    if entry:
                        log_entries.append(entry)
            elif detected_format == 'syslog':
                for line in f:
                    entry = self._parse_syslog_format(line)
                    if entry:
                        log_entries.append(entry)
            else:
                # If format is unrecognized, try CSV
                try:
                    f.seek(0)  # Reset to file beginning
                    reader = csv.reader(f)
                    header = next(reader)
                    
                    # Check if CSV has expected columns
                    if len(header) >= 4 and "timestamp" in header and "severity" in header:
                        timestamp_idx = header.index("timestamp")
                        severity_idx = header.index("severity")
                        source_idx = header.index("source") if "source" in header else -1
                        message_idx = header.index("message") if "message" in header else -1
                        
                        for row in reader:
                            if len(row) > max(timestamp_idx, severity_idx, source_idx, message_idx):
                                timestamp = row[timestamp_idx]
                                severity = row[severity_idx]
                                source = row[source_idx] if source_idx >= 0 else "unknown"
                                message = row[message_idx] if message_idx >= 0 else "No message"
                                
                                log_entries.append(LogEntry(
                                    timestamp=timestamp,
                                    severity=severity,
                                    source=source,
                                    message=message
                                ))
                except Exception as e:
                    # If CSV parsing fails, parse line by line with best guess
                    f.seek(0)  # Reset to file beginning
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            # Basic fallback - assume first part is timestamp, second is severity
                            timestamp = parts[0]
                            severity = parts[1]
                            source = parts[2]
                            message = " ".join(parts[3:])
                            
                            log_entries.append(LogEntry(
                                timestamp=timestamp,
                                severity=severity,
                                source=source,
                                message=message
                            ))
        
        return log_entries
    
    def _parse_standard_format(self, line):
        """Parse a log line in standard format"""
        match = self.patterns['standard'].match(line.strip())
        if match:
            timestamp, severity, source, message = match.groups()
            return LogEntry(timestamp, severity, source, message)
        return None
    
    def _parse_apache_format(self, line):
        """Parse a log line in Apache format"""
        match = self.patterns['apache'].match(line.strip())
        if match:
            ip, timestamp, request, status, size, referrer, user_agent = match.groups()
            # Convert Apache timestamp format
            try:
                # Example: 10/Oct/2023:13:55:36 +0000
                dt = datetime.datetime.strptime(timestamp.split()[0], "%d/%b/%Y:%H:%M:%S")
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                # Keep original if parsing fails
                pass
            
            severity = "INFO"
            if int(status) >= 400 and int(status) < 500:
                severity = "WARNING"
            elif int(status) >= 500:
                severity = "ERROR"
            
            return LogEntry(
                timestamp=timestamp,
                severity=severity,
                source="WebServer",
                message=f"Request: {request}, Status: {status}, Size: {size}"
            )
        return None
    
    def _parse_syslog_format(self, line):
        """Parse a log line in syslog format"""
        match = self.patterns['syslog'].match(line.strip())
        if match:
            timestamp, hostname, service, message = match.groups()
            # Add current year to syslog timestamp (syslog often omits year)
            current_year = datetime.datetime.now().year
            try:
                # Example: Mar 15 12:34:56
                dt = datetime.datetime.strptime(f"{current_year} {timestamp}", "%Y %b %d %H:%M:%S")
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                # Keep original if parsing fails
                pass
            
            # Guess severity from message content
            severity = "INFO"
            if "error" in message.lower():
                severity = "ERROR"
            elif "warning" in message.lower():
                severity = "WARNING"
            elif "critical" in message.lower():
                severity = "CRITICAL"
            
            return LogEntry(
                timestamp=timestamp,
                severity=severity,
                source=service,
                message=message
            )
        return None
