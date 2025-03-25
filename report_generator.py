# report_generator.py - Generates reports from log analysis

import csv
import io

class ReportGenerator:
    def generate_report(self, log_entries, format="txt", stats=None, alerts=None):
        """Generate a report from log entries and statistics"""
        if format == "txt":
            return self._generate_txt_report(log_entries, stats, alerts)
        elif format == "csv":
            return self._generate_csv_report(log_entries, stats, alerts)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_txt_report(self, log_entries, stats, alerts):
        """Generate a plain text report"""
        output = []
        
        # Add header
        output.append("=" * 80)
        output.append("LogLens Analysis Report")
        output.append("=" * 80)
        output.append("")
        
        # Add summary
        output.append(f"Total log entries analyzed: {len(log_entries)}")
        output.append("")
        
        # Add alerts if any
        if alerts:
            output.append("ALERTS:")
            output.append("-" * 80)
            for alert in alerts:
                output.append(f"  {alert}")
            output.append("")
        
        # Add statistics if available
        if stats:
            output.append("STATISTICS:")
            output.append("-" * 80)
            
            # Severity distribution
            output.append("Severity Distribution:")
            for severity, count in stats['severity_counts'].items():
                output.append(f"  {severity}: {count}")
            output.append("")
            
            # Source distribution
            output.append("Source Distribution:")
            for source, count in stats['source_counts'].items():
                output.append(f"  {source}: {count}")
            output.append("")
            
            # Hour distribution
            output.append("Hour Distribution:")
            for hour, count in stats['hour_distribution'].items():
                output.append(f"  {hour:02d}:00 - {hour:02d}:59: {count}")
            output.append("")
            
            # Error rate
            output.append(f"Error Rate: {stats['error_rate']:.2f}%")
            output.append("")
            
            # Common terms
            output.append("Common Terms:")
            for term, count in stats['common_terms'].items():
                output.append(f"  {term}: {count}")
            output.append("")
        
        # Add log entries
        output.append("LOG ENTRIES:")
        output.append("-" * 80)
        for entry in log_entries[:100]:  # Limit to first 100 entries to avoid huge reports
            output.append(str(entry))
        
        if len(log_entries) > 100:
            output.append(f"... and {len(log_entries) - 100} more entries")
        
        return "\n".join(output)
    
    def _generate_csv_report(self, log_entries, stats, alerts):
        """Generate a CSV report"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(["LogLens Analysis Report"])
        writer.writerow([])
        
        # Write summary
        writer.writerow(["Total log entries analyzed", len(log_entries)])
        writer.writerow([])
        
        # Write alerts if any
        if alerts:
            writer.writerow(["ALERTS"])
            for alert in alerts:
                writer.writerow([alert])
            writer.writerow([])
        
        # Write statistics if available
        if stats:
            writer.writerow(["STATISTICS"])
            writer.writerow([])
            
            # Severity distribution
            writer.writerow(["Severity Distribution"])
            writer.writerow(["Severity", "Count"])
            for severity, count in stats['severity_counts'].items():
                writer.writerow([severity, count])
            writer.writerow([])
            
            # Source distribution
            writer.writerow(["Source Distribution"])
            writer.writerow(["Source", "Count"])
            for source, count in stats['source_counts'].items():
                writer.writerow([source, count])
            writer.writerow([])
            
            # Hour distribution
            writer.writerow(["Hour Distribution"])
            writer.writerow(["Hour", "Count"])
            for hour, count in stats['hour_distribution'].items():
                writer.writerow([f"{hour:02d}:00 - {hour:02d}:59", count])
            writer.writerow([])
            
            # Error rate
            writer.writerow(["Error Rate", f"{stats['error_rate']:.2f}%"])
            writer.writerow([])
            
            # Common terms
            writer.writerow(["Common Terms"])
            writer.writerow(["Term", "Count"])
            for term, count in stats['common_terms'].items():
                writer.writerow([term, count])
            writer.writerow([])
        
        # Write log entries
        writer.writerow(["LOG ENTRIES"])
        writer.writerow(["Timestamp", "Severity", "Source", "Message"])
        for entry in log_entries[:100]:  # Limit to first 100 entries
            writer.writerow([entry.timestamp, entry.severity, entry.source, entry.message])
        
        if len(log_entries) > 100:
            writer.writerow([f"... and {len(log_entries) - 100} more entries"])
        
        return output.getvalue()
