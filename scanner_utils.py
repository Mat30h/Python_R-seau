#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Network Scanner Pro - Utility Scripts
Maintenance, analysis, and helper tools
"""

import sqlite3
import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from collections import Counter
import sys

CONFIG_DIR = Path.home() / ".network_scanner_pro"
DB_PATH = CONFIG_DIR / "scan_history.db"


class DatabaseManager:
    """Database maintenance utilities"""
    
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        
    def get_stats(self):
        """Get database statistics"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total scans
            total_scans = cursor.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            
            # Total hosts
            total_hosts = cursor.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
            
            # Unique IPs
            unique_ips = cursor.execute("SELECT COUNT(DISTINCT ip) FROM hosts").fetchone()[0]
            
            # Date range
            date_range = cursor.execute(
                "SELECT MIN(start_time), MAX(start_time) FROM scans"
            ).fetchone()
            
            # Most scanned networks
            networks = cursor.execute("""
                SELECT cidr, COUNT(*) as count 
                FROM scans 
                GROUP BY cidr 
                ORDER BY count DESC 
                LIMIT 10
            """).fetchall()
            
            # Most active hosts
            active_hosts = cursor.execute("""
                SELECT ip, COUNT(*) as scans, 
                       SUM(CASE WHEN ping_ok = 1 THEN 1 ELSE 0 END) as up_count
                FROM hosts
                GROUP BY ip
                ORDER BY scans DESC
                LIMIT 10
            """).fetchall()
            
            return {
                'total_scans': total_scans,
                'total_hosts': total_hosts,
                'unique_ips': unique_ips,
                'date_range': date_range,
                'most_scanned_networks': networks,
                'most_active_hosts': active_hosts
            }
    
    def cleanup_old_scans(self, days=90):
        """Remove scans older than specified days"""
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Get scans to delete
            old_scans = cursor.execute(
                "SELECT scan_id FROM scans WHERE start_time < ?",
                (cutoff_date,)
            ).fetchall()
            
            if not old_scans:
                print(f"No scans older than {days} days found")
                return 0
            
            scan_ids = [s[0] for s in old_scans]
            
            # Delete hosts
            cursor.execute(
                f"DELETE FROM hosts WHERE scan_id IN ({','.join(['?']*len(scan_ids))})",
                scan_ids
            )
            
            # Delete scans
            cursor.execute(
                f"DELETE FROM scans WHERE scan_id IN ({','.join(['?']*len(scan_ids))})",
                scan_ids
            )
            
            conn.commit()
            print(f"Deleted {len(scan_ids)} scans older than {days} days")
            return len(scan_ids)
    
    def export_history(self, output_file):
        """Export complete history to JSON"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get all scans
            scans = cursor.execute("SELECT * FROM scans ORDER BY start_time DESC").fetchall()
            
            export_data = []
            for scan in scans:
                scan_dict = dict(scan)
                
                # Get hosts for this scan
                hosts = cursor.execute(
                    "SELECT * FROM hosts WHERE scan_id = ?",
                    (scan_dict['scan_id'],)
                ).fetchall()
                
                scan_dict['hosts'] = [dict(h) for h in hosts]
                export_data.append(scan_dict)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            print(f"Exported {len(export_data)} scans to {output_file}")
    
    def compare_scans(self, scan_id1, scan_id2):
        """Compare two scans and show differences"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get hosts from both scans
            hosts1 = {
                h['ip']: dict(h) for h in cursor.execute(
                    "SELECT * FROM hosts WHERE scan_id = ?", (scan_id1,)
                ).fetchall()
            }
            
            hosts2 = {
                h['ip']: dict(h) for h in cursor.execute(
                    "SELECT * FROM hosts WHERE scan_id = ?", (scan_id2,)
                ).fetchall()
            }
            
            print("\n" + "="*70)
            print(f"COMPARISON: {scan_id1} vs {scan_id2}")
            print("="*70)
            
            # New hosts
            new_hosts = set(hosts2.keys()) - set(hosts1.keys())
            if new_hosts:
                print(f"\n📍 NEW HOSTS ({len(new_hosts)}):")
                for ip in sorted(new_hosts):
                    print(f"  + {ip}")
            
            # Removed hosts
            removed_hosts = set(hosts1.keys()) - set(hosts2.keys())
            if removed_hosts:
                print(f"\n📍 REMOVED HOSTS ({len(removed_hosts)}):")
                for ip in sorted(removed_hosts):
                    print(f"  - {ip}")
            
            # Changed hosts
            common_hosts = set(hosts1.keys()) & set(hosts2.keys())
            changes = []
            for ip in common_hosts:
                h1, h2 = hosts1[ip], hosts2[ip]
                
                diffs = []
                if h1['ping_ok'] != h2['ping_ok']:
                    diffs.append(f"Status: {h1['ping_ok']} → {h2['ping_ok']}")
                if h1['hostname'] != h2['hostname']:
                    diffs.append(f"Hostname: {h1['hostname']} → {h2['hostname']}")
                if h1['open_ports'] != h2['open_ports']:
                    diffs.append(f"Ports changed")
                
                if diffs:
                    changes.append((ip, diffs))
            
            if changes:
                print(f"\n📍 CHANGED HOSTS ({len(changes)}):")
                for ip, diffs in changes:
                    print(f"  ≈ {ip}")
                    for diff in diffs:
                        print(f"    - {diff}")
            
            print("="*70 + "\n")
    
    def vacuum_database(self):
        """Optimize database (reclaim space)"""
        with sqlite3.connect(self.db_path) as conn:
            size_before = self.db_path.stat().st_size
            conn.execute("VACUUM")
            size_after = self.db_path.stat().st_size
            
            saved = size_before - size_after
            print(f"Database optimized: {size_before/1024:.1f}KB → {size_after/1024:.1f}KB (saved {saved/1024:.1f}KB)")


class ReportAnalyzer:
    """Analyze scan reports and generate insights"""
    
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
    
    def network_health_report(self, cidr):
        """Generate health report for a specific network"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get latest scan for this network
            scan = cursor.execute(
                "SELECT * FROM scans WHERE cidr = ? ORDER BY start_time DESC LIMIT 1",
                (cidr,)
            ).fetchone()
            
            if not scan:
                print(f"No scans found for network {cidr}")
                return
            
            scan_id = scan['scan_id']
            
            # Get all hosts
            hosts = cursor.execute(
                "SELECT * FROM hosts WHERE scan_id = ?", (scan_id,)
            ).fetchall()
            
            print("\n" + "="*70)
            print(f"NETWORK HEALTH REPORT - {cidr}")
            print("="*70)
            print(f"Scan Date: {scan['start_time']}")
            print(f"Scan ID: {scan_id}")
            print("-"*70)
            
            # Availability
            total = len(hosts)
            up = sum(1 for h in hosts if h['ping_ok'])
            print(f"\n📊 AVAILABILITY")
            print(f"  Total hosts: {total}")
            print(f"  Hosts UP: {up} ({up/total*100:.1f}%)")
            print(f"  Hosts DOWN: {total-up} ({(total-up)/total*100:.1f}%)")
            
            # Performance
            rtts = [h['rtt_ms'] for h in hosts if h['rtt_ms']]
            if rtts:
                print(f"\n⚡ PERFORMANCE")
                print(f"  Avg RTT: {sum(rtts)/len(rtts):.2f}ms")
                print(f"  Min RTT: {min(rtts):.2f}ms")
                print(f"  Max RTT: {max(rtts):.2f}ms")
            
            # Services
            all_ports = []
            for h in hosts:
                if h['open_ports']:
                    ports = json.loads(h['open_ports'])
                    all_ports.extend([p['port'] for p in ports])
            
            if all_ports:
                port_counter = Counter(all_ports)
                print(f"\n🌐 SERVICES")
                print(f"  Total open ports: {len(all_ports)}")
                print(f"  Unique services: {len(port_counter)}")
                print(f"  Most common: {port_counter.most_common(5)}")
            
            # Security
            issues_count = sum(
                len(json.loads(h['security_issues'])) if h['security_issues'] else 0
                for h in hosts
            )
            
            if issues_count > 0:
                print(f"\n⚠️  SECURITY")
                print(f"  Total issues: {issues_count}")
                print(f"  Affected hosts: {sum(1 for h in hosts if h['security_issues'])}")
            
            print("="*70 + "\n")
    
    def trending_analysis(self, cidr, days=30):
        """Analyze trends for a network over time"""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get all scans for this network in time period
            scans = cursor.execute("""
                SELECT * FROM scans 
                WHERE cidr = ? AND start_time >= ?
                ORDER BY start_time
            """, (cidr, cutoff)).fetchall()
            
            if len(scans) < 2:
                print(f"Not enough scans for trending (need at least 2, found {len(scans)})")
                return
            
            print("\n" + "="*70)
            print(f"TRENDING ANALYSIS - {cidr} (Last {days} days)")
            print("="*70)
            
            # Availability trend
            print("\n📈 AVAILABILITY TREND")
            for scan in scans:
                date = scan['start_time'][:10]
                pct = scan['hosts_up'] / scan['total_hosts'] * 100
                bar = "█" * int(pct / 2)
                print(f"  {date}: {bar} {pct:.1f}% ({scan['hosts_up']}/{scan['total_hosts']})")
            
            # Port trends
            print("\n📈 PORT ACTIVITY")
            all_port_counts = []
            for scan in scans:
                all_port_counts.append((scan['start_time'][:10], scan['open_ports_found']))
            
            for date, count in all_port_counts:
                bar = "█" * (count // 10)
                print(f"  {date}: {bar} {count} ports")
            
            print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner Pro - Utility Tools"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')
    
    # Cleanup command
    cleanup_parser = subparsers.add_parser('cleanup', help='Clean old scans')
    cleanup_parser.add_argument('--days', type=int, default=90,
                               help='Delete scans older than N days')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export history to JSON')
    export_parser.add_argument('output', help='Output file path')
    
    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare two scans')
    compare_parser.add_argument('scan1', help='First scan ID')
    compare_parser.add_argument('scan2', help='Second scan ID')
    
    # Vacuum command
    vacuum_parser = subparsers.add_parser('vacuum', help='Optimize database')
    
    # Health command
    health_parser = subparsers.add_parser('health', help='Network health report')
    health_parser.add_argument('cidr', help='Network CIDR')
    
    # Trending command
    trend_parser = subparsers.add_parser('trending', help='Trending analysis')
    trend_parser.add_argument('cidr', help='Network CIDR')
    trend_parser.add_argument('--days', type=int, default=30,
                             help='Days to analyze')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        print("Run a scan first to create the database")
        return
    
    db_mgr = DatabaseManager()
    reporter = ReportAnalyzer()
    
    if args.command == 'stats':
        stats = db_mgr.get_stats()
        print("\n" + "="*70)
        print("DATABASE STATISTICS")
        print("="*70)
        print(f"Total Scans: {stats['total_scans']}")
        print(f"Total Host Records: {stats['total_hosts']}")
        print(f"Unique IP Addresses: {stats['unique_ips']}")
        print(f"Date Range: {stats['date_range'][0]} to {stats['date_range'][1]}")
        
        print("\nMost Scanned Networks:")
        for cidr, count in stats['most_scanned_networks']:
            print(f"  {cidr}: {count} scans")
        
        print("\nMost Active Hosts:")
        for ip, scans, up_count in stats['most_active_hosts']:
            print(f"  {ip}: {scans} scans ({up_count} times UP)")
        print("="*70 + "\n")
    
    elif args.command == 'cleanup':
        db_mgr.cleanup_old_scans(args.days)
    
    elif args.command == 'export':
        db_mgr.export_history(args.output)
    
    elif args.command == 'compare':
        db_mgr.compare_scans(args.scan1, args.scan2)
    
    elif args.command == 'vacuum':
        db_mgr.vacuum_database()
    
    elif args.command == 'health':
        reporter.network_health_report(args.cidr)
    
    elif args.command == 'trending':
        reporter.trending_analysis(args.cidr, args.days)


if __name__ == "__main__":
    main()
