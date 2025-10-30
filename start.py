#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🚀 LANCEMENT RAPIDE - Network Scanner Pro

Script de démarrage simplifié avec menu interactif
"""
import subprocess
import sys
import socket
import ipaddress

def clear_screen():
    """Efface l'écran"""
    import os
    os.system('cls' if os.name == 'nt' else 'clear')

def get_local_ip():
    """Récupère l'adresse IP locale"""
    try:
        # Créer une socket pour obtenir l'IP locale
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return None

def ip_to_network(ip, prefix=24):
    """Convertit une IP en réseau CIDR"""
    try:
        interface = ipaddress.IPv4Interface(f"{ip}/{prefix}")
        network = interface.network
        return str(network)
    except Exception:
        return None

def print_header():
    """Affiche l'en-tête"""
    print("╔════════════════════════════════════════════════════════════╗")
    print("║          🌐 NETWORK SCANNER PRO - Menu Principal          ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()

def print_menu():
    """Affiche le menu des options"""
    print("📋 MODES DE SCAN DISPONIBLES:")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    print("  1️⃣  Mode Interactif        (configuration guidée)")
    print("  2️⃣  Scan Quick             (3 ports, ~30s, sans export)")
    print("  3️⃣  Scan Quick + Export    (3 ports, ~30s, CSV+JSON+HTML)")
    print("  4️⃣  Scan Standard          (14 ports, ~2min, sans export)")
    print("  5️⃣  Scan Standard + Export (14 ports, ~2min, CSV+JSON+HTML)")
    print("  6️⃣  Scan Full              (1024 ports, ~15min, sans export)")
    print("  7️⃣  Scan Full + Export     (1024 ports, ~15min, CSV+JSON+HTML)")
    print("  8️⃣  Scan Security          (18 ports, ~3min, sans export)")
    print("  9️⃣  Scan Security + Export (18 ports, ~3min, CSV+JSON+HTML)")
    print("  🔟 Scan Personnalisé       (saisie manuelle des paramètres)")
    print()
    print("  0️⃣  Quitter")
    print()
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

def get_network_input():
    """Demande le réseau à scanner avec option auto-détection"""
    print()
    print("🌐 Réseau à scanner:")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    
    # Détecter l'IP locale
    local_ip = get_local_ip()
    
    if local_ip:
        local_network = ip_to_network(local_ip, 24)
        print(f"  📍 IP locale détectée: {local_ip}")
        print(f"  🌐 Réseau suggéré: {local_network}")
        print()
        print("  1️⃣  Utiliser le réseau détecté automatiquement")
        print("  2️⃣  Entrer un réseau manuellement")
        print()
        
        choice = input("  → Votre choix (1 ou 2): ").strip()
        
        if choice == "1":
            print(f"\n  ✅ Réseau sélectionné: {local_network}")
            return local_network
        elif choice == "2":
            print()
            print("  Exemples: 192.168.1.0/24, 10.0.0.0/16, 172.16.1.0/24")
            network = input("  → Réseau (CIDR): ").strip()
            return network
        else:
            print("\n  ⚠️  Choix invalide, utilisation du réseau détecté")
            return local_network
    else:
        # Pas d'IP détectée, saisie manuelle
        print("  ⚠️  Impossible de détecter l'IP locale")
        print("  Exemples: 192.168.1.0/24, 10.0.0.0/16, 172.16.1.0/24")
        network = input("  → Réseau (CIDR): ").strip()
        return network

def run_scan(profile=None, export=None, network=None, custom_cmd=None):
    """Lance le scan avec les paramètres spécifiés"""
    try:
        if custom_cmd:
            cmd = [sys.executable, "network_scanner_pro.py"] + custom_cmd
        elif profile:
            cmd = [sys.executable, "network_scanner_pro.py"]
            if network:
                cmd.extend(["-c", network])
            cmd.extend(["-p", profile])
            if export:
                cmd.append("--export-all")
        else:
            # Mode interactif
            cmd = [sys.executable, "network_scanner_pro.py"]
        
        print()
        print("🚀 Lancement du scan...")
        print(f"💻 Commande: {' '.join(cmd)}")
        print()
        
        subprocess.run(cmd, check=True)
        
        print()
        print("✅ Scan terminé avec succès!")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Scanner interrompu par l'utilisateur")
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Erreur lors du scan (code {e.returncode})")
    except FileNotFoundError:
        print("\n❌ Erreur: network_scanner_pro.py introuvable")
        print("   Assurez-vous d'être dans le bon répertoire")
    except Exception as e:
        print(f"\n❌ Erreur: {e}")

def main():
    """Fonction principale"""
    while True:
        clear_screen()
        print_header()
        print_menu()
        
        try:
            choice = input("Choisissez une option (0-10): ").strip()
            
            if choice == "0":
                print("\n👋 Au revoir!")
                sys.exit(0)
            
            elif choice == "1":
                # Mode interactif
                print("\n📍 Mode interactif - Le scanner vous guidera")
                run_scan()
                
            elif choice == "2":
                # Quick sans export
                network = get_network_input()
                if network:
                    run_scan(profile="quick", network=network)
                
            elif choice == "3":
                # Quick avec export
                network = get_network_input()
                if network:
                    run_scan(profile="quick", export="csv,json,html", network=network)
                
            elif choice == "4":
                # Standard sans export
                network = get_network_input()
                if network:
                    run_scan(profile="standard", network=network)
                
            elif choice == "5":
                # Standard avec export
                network = get_network_input()
                if network:
                    run_scan(profile="standard", export="csv,json,html", network=network)
                
            elif choice == "6":
                # Full sans export
                network = get_network_input()
                if network:
                    run_scan(profile="full", network=network)
                
            elif choice == "7":
                # Full avec export
                network = get_network_input()
                if network:
                    run_scan(profile="full", export="csv,json,html", network=network)
                
            elif choice == "8":
                # Security sans export
                network = get_network_input()
                if network:
                    run_scan(profile="security", network=network)
                
            elif choice == "9":
                # Security avec export
                network = get_network_input()
                if network:
                    run_scan(profile="security", export="csv,json,html", network=network)
                
            elif choice == "10":
                # Scan personnalisé
                print("\n⚙️  Configuration personnalisée:")
                network = input("   Réseau (CIDR): ").strip()
                ports = input("   Ports (ex: 22,80,443): ").strip()
                threads = input("   Threads (ex: 100): ").strip()
                export = input("   Export tous formats? (o/n): ").strip().lower()
                
                cmd = []
                if network:
                    cmd.extend(["-c", network])
                if ports:
                    cmd.extend(["--ports", ports])
                if threads:
                    cmd.extend(["-t", threads])
                if export == 'o':
                    cmd.append("--export-all")
                
                if cmd:
                    run_scan(custom_cmd=cmd)
                else:
                    print("\n⚠️  Aucun paramètre saisi, mode interactif...")
                    run_scan()
            
            else:
                print("\n❌ Option invalide! Choisissez entre 0 et 10.")
                input("\nAppuyez sur Entrée pour continuer...")
                continue
            
            # Demander si on veut relancer
            print()
            choice = input("Voulez-vous effectuer un autre scan? (o/n): ").strip().lower()
            if choice != 'o':
                print("\n👋 Au revoir!")
                break
                
        except KeyboardInterrupt:
            print("\n\n⚠️  Programme interrompu par l'utilisateur")
            print("👋 Au revoir!")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Erreur: {e}")
            input("\nAppuyez sur Entrée pour continuer...")

if __name__ == "__main__":
    main()
