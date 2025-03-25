# loglens.py - Main application entry point

import argparse
import sys
from log_parser import LogParser
from log_analyzer import LogAnalyzer
from report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="LogLens - A log analysis and monitoring tool")
    parser.add_argument("log_file", help="Path to the log file to analyze")
    parser.add_argument("-f", "--format", choices=["txt", "csv"], default="txt", help="Output format (default: txt)")
    parser.add_argument("-o", "--output", help="Output file path (default: stdout)")
    parser.add_argument("-d", "--date-range", help="Filter by date range (format: YYYY-MM-DD:YYYY-MM-DD)")
    parser.add_argument("-s", "--severity", choices=["INFO", "WARNING", "ERROR", "CRITICAL"], help="Filter by severity level")
    parser.add_argument("-p", "--pattern", help="Filter by regex pattern")
    parser.add_argument("--stats", action="store_true", help="Generate statistics")
    parser.add_argument("--alerts", help="Generate alerts for error rates above threshold (float value)")
    
    args = parser.parse_args()
    
    try:
        # Initialize components
        parser = LogParser()
        analyzer = LogAnalyzer()
        generator = ReportGenerator()
        
        # Parse logs
        log_entries = parser.parse_file(args.log_file)
        
        # Apply filters
        if args.date_range:
            start_date, end_date = args.date_range.split(":")
            log_entries = analyzer.filter_by_date(log_entries, start_date, end_date)
        
        if args.severity:
            log_entries = analyzer.filter_by_severity(log_entries, args.severity)
        
        if args.pattern:
            log_entries = analyzer.filter_by_pattern(log_entries, args.pattern)
        
        # Analyze logs
        if args.stats:
            stats = analyzer.generate_statistics(log_entries)
        else:
            stats = None
        
        # Generate alerts if threshold is provided
        alerts = None
        if args.alerts:
            threshold = float(args.alerts)
            alerts = analyzer.check_alerts(log_entries, threshold)
        
        # Generate report
        report = generator.generate_report(log_entries, format=args.format, stats=stats, alerts=alerts)
        
        # Output report
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
        else:
            print(report)
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())
