# log_analyzer.py - Analyzes log entries and extracts metrics

import re
import datetime
from collections import Counter, defaultdict

class LogAnalyzer:
    def filter_by_date(self, log_entries, start_date, end_date):
        """Filter log entries by date range"""
        filtered_entries = []
        
        try:
            # Parse start and end dates
            start_dt = datetime.datetime.strptime(start_date, "%Y-%m-%d")
            end_dt = datetime.datetime.strptime(end_date, "%Y-%m-%d")
            end_dt = end_dt.replace(hour=23, minute=59, second=59)  # Include entire end day
            
            for entry in log_entries:
                try:
                    # Parse entry timestamp (handle different formats)
                    entry_dt = None
                    
                    # Try different timestamp formats
                    formats = [
                        "%Y-%m-%d %H:%M:%S",
                        "%Y-%m-%d %H:%M:%S.%f",
                        "%Y/%m/%d %H:%M:%S"
                    ]
                    
                    for fmt in formats:
                        try:
                            entry_dt = datetime.datetime.strptime(entry.timestamp, fmt)
                            break
                        except ValueError:
                            continue
                    
                    if entry_dt and start_dt <= entry_dt <= end_dt:
                        filtered_entries.append(entry)
                except ValueError:
                    # Skip entries with unparseable timestamps
                    continue
                    
        except ValueError as e:
            raise ValueError(f"Invalid date format. Use YYYY-MM-DD: {e}")
            
        return filtered_entries
    
    def filter_by_severity(self, log_entries, severity):
        """Filter log entries by severity level"""
        return [entry for entry in log_entries if entry.severity == severity]
    
    def filter_by_pattern(self, log_entries, pattern):
        """Filter log entries by regex pattern"""
        try:
            regex = re.compile(pattern)
            return [entry for entry in log_entries if regex.search(entry.message)]
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
    
    def generate_statistics(self, log_entries):
        """Generate statistics from log entries"""
        stats = {}
        
        # Count entries by severity
        severity_counts = Counter(entry.severity for entry in log_entries)
        stats['severity_counts'] = dict(severity_counts)
        
        # Count entries by source
        source_counts = Counter(entry.source for entry in log_entries)
        stats['source_counts'] = dict(source_counts)
        
        # Group by hour of day to see time patterns
        hour_counts = defaultdict(int)
        for entry in log_entries:
            try:
                # Try different timestamp formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S"]:
                    try:
                        dt = datetime.datetime.strptime(entry.timestamp, fmt)
                        hour_counts[dt.hour] += 1
                        break
                    except ValueError:
                        continue
            except Exception:
                # Skip entries with unparseable timestamps
                continue
        
        stats['hour_distribution'] = dict(sorted(hour_counts.items()))
        
        # Calculate error rate
        total_entries = len(log_entries)
        error_entries = sum(1 for entry in log_entries if entry.severity in ["ERROR", "CRITICAL"])
        stats['error_rate'] = (error_entries / total_entries) * 100 if total_entries > 0 else 0
        
        # Find common patterns in messages
        word_counts = Counter()
        for entry in log_entries:
            words = re.findall(r'\b\w+\b', entry.message.lower())
            word_counts.update(words)
        
        # Filter out common words
        common_words = {"the", "a", "an", "and", "or", "but", "is", "are", "was", "were"}
        for word in common_words:
            if word in word_counts:
                del word_counts[word]
        
        stats['common_terms'] = dict(word_counts.most_common(10))
        
        return stats
    
    def check_alerts(self, log_entries, threshold):
        """Check if error rate exceeds threshold and generate alerts"""
        alerts = []
        
        # Count entries by severity
        severity_counts = Counter(entry.severity for entry in log_entries)
        total_entries = len(log_entries)
        
        # Calculate error rate
        error_count = severity_counts.get("ERROR", 0) + severity_counts.get("CRITICAL", 0)
        error_rate = (error_count / total_entries) * 100 if total_entries > 0 else 0
        
        if error_rate > threshold:
            alerts.append(f"ALERT: Error rate of {error_rate:.2f}% exceeds threshold of {threshold:.2f}%")
        
        # Group errors by source
        source_errors = defaultdict(int)
        for entry in log_entries:
            if entry.severity in ["ERROR", "CRITICAL"]:
                source_errors[entry.source] += 1
        
        # Check if any source has a concerning error count
        for source, count in source_errors.items():
            source_error_rate = (count / total_entries) * 100 if total_entries > 0 else 0
            if source_error_rate > threshold:
                alerts.append(f"ALERT: Source '{source}' has error rate of {source_error_rate:.2f}%")
        
        return alerts if alerts else None
