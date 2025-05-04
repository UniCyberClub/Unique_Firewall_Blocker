import ctypes
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, PhotoImage, simpledialog
import subprocess
import socket
from PIL import Image, ImageTk
import threading
import queue
import time
import re
from plyer import notification

class UniqueFirewallBlocker:
    def __init__(self, root):
        self.root = root
        self.connection_queue = queue.Queue()
        self.last_foreign_ips = set()
        self.known_networks = self.get_known_networks()
        self.excluded_networks = self.load_excluded_networks()
        self.setup_ui()
        self.start_connection_monitor()
        
    def setup_ui(self):
        self.root.title("Unique Firewall Blocker")
        self.root.geometry("1000x750")
        self.root.resizable(True, True)
        self.root.configure(bg='#2c3e50')
        self.setup_custom_title_bar()
        self.load_images()
        main_frame = tk.Frame(self.root, bg='#2c3e50')
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left panel (controls)
        left_panel = tk.Frame(main_frame, bg='#2c3e50')
        left_panel.pack(side='left', fill='y', padx=5, pady=5)
        
        # Right panel (connections)
        right_panel = tk.Frame(main_frame, bg='#2c3e50')
        right_panel.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        # Header
        header_frame = tk.Frame(left_panel, bg='#2c3e50')
        header_frame.pack(fill='x', pady=5)
        
        self.ninja_label = tk.Label(header_frame, image=self.ninja_img, bg='#2c3e50')
        self.ninja_label.pack(side='left', padx=5)
        
        title_label = tk.Label(
            header_frame, 
            text="UNIQUE FIREWALL BLOCKER", 
            font=('Impact', 16), 
            fg='#e74c3c', 
            bg='#2c3e50',
            padx=10
        )
        title_label.pack(side='left', pady=5)
        
        # Input section
        input_frame = tk.Frame(left_panel, bg='#2c3e50')
        input_frame.pack(fill='x', pady=10)
        
        tk.Label(
            input_frame, 
            text="Enter IP Address or Domain:", 
            font=('Arial', 11, 'bold'), 
            fg='#ecf0f1', 
            bg='#2c3e50'
        ).pack(anchor='w', pady=5)
        
        self.entry = tk.Entry(
            input_frame, 
            width=30, 
            font=('Arial', 12),
            bg='#34495e',
            fg='#ffffff',
            insertbackground='white',
            relief='flat',
            borderwidth=2,
            highlightthickness=1,
            highlightbackground="#e74c3c",
            highlightcolor="#e74c3c",
            selectbackground="#e74c3c"
        )
        self.entry.pack(fill='x', pady=5, ipady=5)
        
        # Unique Buttons
        btn_frame = tk.Frame(left_panel, bg='#2c3e50')
        btn_frame.pack(fill='x', pady=10)
        
        self.block_btn = tk.Button(
            btn_frame, 
            text="BLOCK CONNECTION", 
            command=self.block_connection,
            font=('Arial', 11, 'bold'),
            bg='#e74c3c',
            fg='white',
            activebackground='#c0392b',
            activeforeground='white',
            relief='raised',
            borderwidth=2,
            padx=15,
            pady=5,
            cursor='hand2'
        )
        self.block_btn.pack(fill='x', pady=5)
        
        self.unblock_btn = tk.Button(
            btn_frame, 
            text="UNBLOCK CONNECTION", 
            command=self.unblock_connection,
            font=('Arial', 11, 'bold'),
            bg='#27ae60',
            fg='white',
            activebackground='#219653',
            activeforeground='white',
            relief='raised',
            borderwidth=2,
            padx=15,
            pady=5,
            cursor='hand2'
        )
        self.unblock_btn.pack(fill='x', pady=5)
        
        # Block selected connection button
        self.block_selected_btn = tk.Button(
            btn_frame, 
            text="BLOCK SELECTED", 
            command=self.block_selected_connection,
            font=('Arial', 11, 'bold'),
            bg='#3498db',
            fg='white',
            activebackground='#2980b9',
            activeforeground='white',
            relief='raised',
            borderwidth=2,
            padx=15,
            pady=5,
            cursor='hand2'
        )
        self.block_selected_btn.pack(fill='x', pady=5)
        
        # Status area
        self.status_frame = tk.Frame(left_panel, bg='#34495e', bd=1, relief='sunken')
        self.status_frame.pack(fill='x', pady=10, ipady=5)
        
        self.status_label = tk.Label(
            self.status_frame, 
            text="Ready to execute firewall commands...", 
            font=('Arial', 9, 'bold'), 
            fg='#ecf0f1', 
            bg='#34495e',
            wraplength=250,
            justify='left'
        )
        self.status_label.pack(pady=2, padx=5, anchor='w')
        
        # Connections monitor
        conn_frame = tk.Frame(right_panel, bg='#2c3e50')
        conn_frame.pack(fill='both', expand=True)
        
        # Connection monitor header with improved readability
        conn_header = tk.Frame(conn_frame, bg='#e74c3c')
        conn_header.pack(fill='x', pady=(0,5))
        
        tk.Label(
            conn_header, 
            text="ACTIVE CONNECTIONS (Refreshing every 5 sec)", 
            font=('Arial', 12, 'bold'), 
            fg='white', 
            bg='#e74c3c',
            padx=10,
            pady=5
        ).pack(side='left')
        
        # Treeview for connections
        self.tree = ttk.Treeview(
            conn_frame,
            columns=('Proto', 'Local', 'Foreign', 'State', 'PID'),
            show='headings',
            selectmode='browse'
        )
        
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview",
            background="#34495e",
            foreground="white",
            fieldbackground="#34495e",
            borderwidth=0,
            font=('Arial', 10),
            rowheight=25
        )
        style.configure("Treeview.Heading",
            background="#e74c3c",
            foreground="white",
            font=('Arial', 10, 'bold'),
            relief='flat',
            padding=5
        )
        style.map('Treeview',
            background=[('selected', '#3498db')],
            foreground=[('selected', 'white')]
        )
        
        # Configure columns
        self.tree.heading('Proto', text='Protocol', anchor='center')
        self.tree.heading('Local', text='Local Address', anchor='w')
        self.tree.heading('Foreign', text='Foreign Address', anchor='w')
        self.tree.heading('State', text='State', anchor='center')
        self.tree.heading('PID', text='PID', anchor='center')
        
        self.tree.column('Proto', width=80, anchor='center')
        self.tree.column('Local', width=200, anchor='w')
        self.tree.column('Foreign', width=200, anchor='w')
        self.tree.column('State', width=100, anchor='center')
        self.tree.column('PID', width=80, anchor='center')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(conn_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(fill='both', expand=True)
        
        # Control buttons frame
        ctrl_btn_frame = tk.Frame(right_panel, bg='#2c3e50')
        ctrl_btn_frame.pack(fill='x', pady=5)
        
        # Refresh button
        refresh_btn = tk.Button(
            ctrl_btn_frame, 
            text="⟳ REFRESH NOW", 
            command=self.refresh_connections,
            font=('Arial', 10, 'bold'),
            bg='#3498db',
            fg='white',
            activebackground='#2980b9',
            activeforeground='white',
            relief='raised',
            borderwidth=1,
            padx=15,
            pady=3,
            cursor='hand2'
        )
        refresh_btn.pack(side='left', padx=5)
        
        # Auto-block toggle
        self.auto_block_var = tk.BooleanVar(value=False)
        auto_block_btn = tk.Checkbutton(
            ctrl_btn_frame,
            text="Auto-Block Suspicious IPs",
            variable=self.auto_block_var,
            font=('Arial', 10, 'bold'),
            fg='#ecf0f1',
            bg='#2c3e50',
            activebackground='#2c3e50',
            activeforeground='#ecf0f1',
            selectcolor='#34495e',
            cursor='hand2'
        )
        auto_block_btn.pack(side='left', padx=10)
        
        # Network management button
        network_btn = tk.Button(
            ctrl_btn_frame,
            text="Manage Networks",
            command=self.manage_networks,
            font=('Arial', 10, 'bold'),
            bg='#9b59b6',
            fg='white',
            activebackground='#8e44ad',
            activeforeground='white',
            relief='raised',
            borderwidth=1,
            padx=15,
            pady=3,
            cursor='hand2'
        )
        network_btn.pack(side='left', padx=5)
        
        # Footer
        footer_frame = tk.Frame(left_panel, bg='#2c3e50')
        footer_frame.pack(fill='x', pady=5, side='bottom')
        
        tk.Label(
            footer_frame, 
            text="© 2025 Unique Firewall Blocker | Coded by Auxgrep", 
            font=('Arial', 8), 
            fg='#7f8c8d', 
            bg='#2c3e50'
        ).pack(side='right')
        
    def setup_custom_title_bar(self):
        # Remove default title bar
        self.root.overrideredirect(True)
        
        # Create custom title bar
        title_bar = tk.Frame(self.root, bg='#121212', relief='raised', bd=0, height=30)
        title_bar.pack(fill='x')
        
        # Title
        title_label = tk.Label(
            title_bar, 
            text='Unique Firewall Blocker', 
            bg='#121212', 
            fg='#e74c3c', 
            font=('Arial', 10, 'bold')
        )
        title_label.pack(side='left', padx=10)
        
        # Close button
        close_button = tk.Button(
            title_bar, 
            text='✕', 
            bg='#121212', 
            fg='white', 
            bd=0, 
            font=('Arial', 12, 'bold'),
            activebackground='#e74c3c',
            command=self.root.destroy,
            padx=10,
            cursor='hand2'
        )
        close_button.pack(side='right')
        
        # Bind events for moving window
        title_bar.bind('<B1-Motion>', self.move_window)
        title_bar.bind('<Button-1>', self.get_pos)
        title_label.bind('<B1-Motion>', self.move_window)
        title_label.bind('<Button-1>', self.get_pos)
        
    def move_window(self, event):
        x = self.root.winfo_pointerx() - self._x
        y = self.root.winfo_pointery() - self._y
        self.root.geometry(f'+{x}+{y}')
        
    def get_pos(self, event):
        self._x = event.x
        self._y = event.y
        
    def load_images(self):
        try:
            self.ninja_img = PhotoImage(file='ninja.png').subsample(2, 2)
        except:
            self.ninja_img = PhotoImage(width=48, height=48)
            for x in range(48):
                for y in range(48):
                    if (x-24)**2 + (y-24)**2 <= 225:  
                        self.ninja_img.put('#e74c3c', (x, y))
    
    def update_status(self, message, color='#ecf0f1'):
        self.status_label.config(text=message, fg=color)
        self.root.update_idletasks()
        
    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    
    def resolve_domain(self, domain):
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None
    
    def run_firewall_command(self, command):
        try:
            subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def is_ip(self, text):
        parts = text.split('.')
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    
    # Get list of known local networks from network interfaces
    def get_known_networks(self):
        known_networks = set()
        try:
            # Get network interfaces using ipconfig
            result = subprocess.run(['ipconfig'], capture_output=True, text=True)
            interfaces = result.stdout.split('\n\n')
            
            # null with IPv4 addresses
            ip_pattern = r'IPv4 Address.*?(\d+\.\d+\.\d+\.\d+)'
            for interface in interfaces:
                matches = re.findall(ip_pattern, interface)
                for ip in matches:
                    # Add the /24 network
                    network = '.'.join(ip.split('.')[:3]) + '.0/24'
                    known_networks.add(network)
        except:
            pass
            
        return known_networks
    
    def load_excluded_networks(self):
        excluded_networks = set()
        try:
            if os.path.exists('excluded_networks.txt'):
                with open('excluded_networks.txt', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            excluded_networks.add(line)
        except:
            pass
            
        # Add default private networks if empty , you can add/edit more on gui
        if not excluded_networks:
            excluded_networks.update([
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16',
                '127.0.0.0/8'
            ])
            self.excluded_nets(excluded_networks)
            
        return excluded_networks
    
    def excluded_nets(self, networks):
        try:
            with open('excluded_networks.txt', 'w') as f:
                f.write("# User-defined excluded networks\n")
                f.write("# Format: network/mask (e.g., 192.168.1.0/24)\n")
                for network in sorted(networks):
                    f.write(f"{network}\n")
        except:
            pass
    
    def manage_networks(self):
        manage_win = tk.Toplevel(self.root)
        manage_win.title("Manage Excluded Networks")
        manage_win.geometry("500x400")
        manage_win.resizable(False, False)
        manage_win.configure(bg='#2c3e50')
        
        # Center the window
        window_width = manage_win.winfo_reqwidth()
        window_height = manage_win.winfo_reqheight()
        position_right = int(manage_win.winfo_screenwidth()/2 - window_width/2)
        position_down = int(manage_win.winfo_screenheight()/2 - window_height/2)
        manage_win.geometry(f"+{position_right}+{position_down}")
        
        # Title
        tk.Label(
            manage_win,
            text="EXCLUDED NETWORKS",
            font=('Arial', 12, 'bold'),
            fg='#e74c3c',
            bg='#2c3e50',
            pady=10
        ).pack(fill='x')
        
        # Explanation
        tk.Label(
            manage_win,
            text="These networks will not trigger security alerts:",
            font=('Arial', 10),
            fg='#ecf0f1',
            bg='#2c3e50'
        ).pack(fill='x', pady=5)
        
        # Network list
        list_frame = tk.Frame(manage_win, bg='#34495e')
        list_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side='right', fill='y')
        
        self.network_list = tk.Listbox(
            list_frame,
            bg='#34495e',
            fg='#ecf0f1',
            selectbackground='#3498db',
            selectforeground='white',
            font=('Arial', 10),
            yscrollcommand=scrollbar.set
        )
        self.network_list.pack(fill='both', expand=True)
        
        scrollbar.config(command=self.network_list.yview)
        
        # Populate list
        for network in sorted(self.excluded_networks):
            self.network_list.insert('end', network)
        
        # Control buttons
        btn_frame = tk.Frame(manage_win, bg='#2c3e50')
        btn_frame.pack(fill='x', pady=10)
        
        # Add button
        add_btn = tk.Button(
            btn_frame,
            text="Add Network",
            command=self.add_network,
            font=('Arial', 10, 'bold'),
            bg='#27ae60',
            fg='white',
            padx=10,
            pady=3
        )
        add_btn.pack(side='left', padx=5)
        
        # Remove button
        remove_btn = tk.Button(
            btn_frame,
            text="Remove Selected",
            command=self.remove_network,
            font=('Arial', 10, 'bold'),
            bg='#e74c3c',
            fg='white',
            padx=10,
            pady=3
        )
        remove_btn.pack(side='left', padx=5)
        
        # Save button
        save_btn = tk.Button(
            btn_frame,
            text="Save Changes",
            command=lambda: [self.save_network_changes(), manage_win.destroy()],
            font=('Arial', 10, 'bold'),
            bg='#3498db',
            fg='white',
            padx=10,
            pady=3
        )
        save_btn.pack(side='right', padx=5)
    
    #  Add a new network to the excluded list
    def add_network(self):
        network = simpledialog.askstring(
            "Add Network",
            "Enter network in CIDR notation (e.g., 192.168.1.0/24):",
            parent=self.root
        )
        
        if network:
            # Validate network format
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', network):
                self.network_list.insert('end', network)
            else:
                messagebox.showerror("Invalid Format", "Please use CIDR notation (e.g., 192.168.1.0/24)")
    
    # Remove selected network from excluded list
    def remove_network(self):
        selection = self.network_list.curselection()
        if selection:
            self.network_list.delete(selection[0])
    
    def save_network_changes(self):
        networks = set(self.network_list.get(0, 'end'))
        self.excluded_networks = networks
        self.excluded_nets(networks)
        messagebox.showinfo("Saved", "Network exclusions updated successfully")
    
    # Check if IP is in excluded network ranges
    def is_private_ip(self, ip):
        if not self.is_ip(ip):
            return False
            
        # Check against excluded networks
        ip_parts = list(map(int, ip.split('.')))
        
        for network in self.excluded_networks:
            net_addr, net_bits = network.split('/')
            net_parts = list(map(int, net_addr.split('.')))
            net_bits = int(net_bits)
            
            # Convert to binary and compare network portions
            match = True
            for i in range(4):
                if net_bits <= 0:
                    break
                bits = min(8, net_bits)
                mask = (0xFF << (8 - bits)) & 0xFF
                if (ip_parts[i] & mask) != (net_parts[i] & mask):
                    match = False
                    break
                net_bits -= 8
                
            if match:
                return True
                
        return False
    
    def get_connections(self):
        try:
            result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError:
            return None
    
    def parse_connections(self, netstat_output):
        connections = []
        lines = netstat_output.split('\n')
        for line in lines:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 5 and parts[0] in ['TCP', 'UDP']:
                proto = parts[0]
                local = parts[1]
                foreign = parts[2]
                state = parts[3] if proto == 'TCP' else ''
                pid = parts[4] if proto == 'TCP' else parts[3]
                connections.append((proto, local, foreign, state, pid))
        return connections
    
    def refresh_connections(self):
        netstat_output = self.get_connections()
        if netstat_output:
            connections = self.parse_connections(netstat_output)
            self.update_connections_tree(connections)
            self.update_status("✓ Connections refreshed", '#2ecc71')
            self.check_new_outbound(connections)
        else:
            self.update_status("✗ Failed to get connections", '#e74c3c')
    
    def update_connections_tree(self, connections):
        # Clear current items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add new connections with color coding
        for conn in connections:
            foreign_addr = conn[2]
            ip = foreign_addr.split(':')[0] if ':' in foreign_addr else foreign_addr
            
            if self.is_ip(ip):
                if not self.is_private_ip(ip) and ip != '0.0.0.0' and ip != '127.0.0.1':
                    # Foreign IP - tag with red
                    self.tree.insert('', 'end', values=conn, tags=('foreign',))
                else:
                    # Local IP - normal
                    self.tree.insert('', 'end', values=conn)
            else:
                self.tree.insert('', 'end', values=conn)
        
        # Configure tag colors
        self.tree.tag_configure('foreign', foreground='#ff9999')
    
    def check_new_outbound(self, connections):
        current_foreign_ips = set()
        
        for conn in connections:
            foreign_addr = conn[2]  # Foreign address column
            if ':' in foreign_addr:
                ip = foreign_addr.split(':')[0]
                if (self.is_ip(ip) and 
                    not self.is_private_ip(ip) and 
                    ip != '0.0.0.0' and 
                    ip != '127.0.0.1'):
                    current_foreign_ips.add(ip)
        
        new_ips = current_foreign_ips - self.last_foreign_ips
        self.last_foreign_ips = current_foreign_ips
        
        if new_ips and self.auto_block_var.get():
            for ip in new_ips:
                self.auto_block_foreign_ip(ip)
    
    def auto_block_foreign_ip(self, ip):
        try:
            notification.notify(
                title='Suspicious Outbound Connection Detected',
                message=f'Foreign IP: {ip}\nThis IP is outside your trusted networks.',
                app_name='Unique Firewall Blocker',
                timeout=10
            )
        except:
            # Fallback to tkinter messagebox if plyer fails
            messagebox.showwarning(
                "Suspicious Outbound Connection Detected",
                f"Foreign IP: {ip}\nThis IP is outside your trusted networks."
            )
        
        # Create notification window
        notify_win = tk.Toplevel(self.root)
        notify_win.title("Suspicious Outbound Connection Detected")
        notify_win.geometry("450x220")
        notify_win.resizable(False, False)
        notify_win.configure(bg='#2c3e50')
        notify_win.attributes('-topmost', True)
        
        # Center the notification window
        window_width = notify_win.winfo_reqwidth()
        window_height = notify_win.winfo_reqheight()
        position_right = int(notify_win.winfo_screenwidth()/2 - window_width/2)
        position_down = int(notify_win.winfo_screenheight()/2 - window_height/2)
        notify_win.geometry(f"+{position_right}+{position_down}")
        
        # Notification content
        tk.Label(
            notify_win,
            text="SUSPICIOUS OUTBOUND CONNECTION",
            font=('Arial', 12, 'bold'),
            fg='#e74c3c',
            bg='#2c3e50',
            pady=10
        ).pack(fill='x')
        
        tk.Label(
            notify_win,
            text=f"Foreign IP: {ip}",
            font=('Arial', 11),
            fg='#ecf0f1',
            bg='#2c3e50',
            pady=5
        ).pack(fill='x')
        
        tk.Label(
            notify_win,
            text="This IP is outside your trusted networks.",
            font=('Arial', 10),
            fg='#ecf0f1',
            bg='#2c3e50'
        ).pack(fill='x')
        
        tk.Label(
            notify_win,
            text="Would you like to block this connection?",
            font=('Arial', 10),
            fg='#ecf0f1',
            bg='#2c3e50',
            pady=10
        ).pack(fill='x')
        
        # Action buttons
        btn_frame = tk.Frame(notify_win, bg='#2c3e50')
        btn_frame.pack(pady=15)
        
        def block_and_close():
            self.entry.delete(0, tk.END)
            self.entry.insert(0, ip)
            self.block_connection()
            notify_win.destroy()
        
        block_btn = tk.Button(
            btn_frame,
            text="BLOCK",
            command=block_and_close,
            font=('Arial', 10, 'bold'),
            bg='#e74c3c',
            fg='white',
            padx=20,
            pady=5
        )
        block_btn.pack(side='left', padx=10)
        
        allow_btn = tk.Button(
            btn_frame,
            text="ALLOW",
            command=notify_win.destroy,
            font=('Arial', 10, 'bold'),
            bg='#27ae60',
            fg='white',
            padx=20,
            pady=5
        )
        allow_btn.pack(side='left', padx=10)
        
        # Add to known networks button
        known_btn = tk.Button(
            btn_frame,
            text="TRUST THIS NETWORK",
            command=lambda: [self.add_to_known_networks(ip), notify_win.destroy()],
            font=('Arial', 10, 'bold'),
            bg='#3498db',
            fg='white',
            padx=10,
            pady=5
        )
        known_btn.pack(side='left', padx=10)
    
    # here Add the /24 network of the given IP to known networks
    def add_to_known_networks(self, ip):
        if self.is_ip(ip):
            network = '.'.join(ip.split('.')[:3]) + '.0/24'
            self.excluded_networks.add(network)
            self.excluded_nets(self.excluded_networks)
            self.update_status(f"✓ Added {network} to trusted networks", '#2ecc71')
    
    def connection_monitor_thread(self):
        while True:
            netstat_output = self.get_connections()
            if netstat_output:
                connections = self.parse_connections(netstat_output)
                self.connection_queue.put(connections)
            time.sleep(5)
    
    def process_connection_queue(self):
        try:
            while True:
                connections = self.connection_queue.get_nowait()
                self.update_connections_tree(connections)
                self.check_new_outbound(connections)
        except queue.Empty:
            pass
        self.root.after(100, self.process_connection_queue)
    
    def start_connection_monitor(self):
        monitor_thread = threading.Thread(target=self.connection_monitor_thread, daemon=True)
        monitor_thread.start()
        self.root.after(100, self.process_connection_queue)
    
    def block_connection(self):
        target = self.entry.get().strip()
        if not target:
            self.update_status("✖ Error: Please enter an IP address or domain", '#e74c3c')
            messagebox.showwarning("Input Error", "Please enter an IP address or domain name to block.")
            return

        if not self.is_ip(target):
            self.update_status(f"⌛ Resolving domain: {target}...", '#f1c40f')
            ip = self.resolve_domain(target)
            if ip is None:
                self.update_status(f"✖ Error: Failed to resolve {target}", '#e74c3c')
                messagebox.showerror("DNS Error", f"Failed to resolve domain: {target}")
                return
        else:
            ip = target

        self.update_status(f"⚔ Blocking {ip}...", '#f1c40f')
        self.block_btn.config(state='disabled', bg='#95a5a6')
        self.unblock_btn.config(state='disabled', bg='#95a5a6')
        self.block_selected_btn.config(state='disabled', bg='#95a5a6')
        self.root.update_idletasks()
        
        name = f"Block_{ip.replace('.', '_')}"
        inbound = f'netsh advfirewall firewall add rule name="{name}_IN" dir=in action=block remoteip={ip} enable=yes'
        outbound = f'netsh advfirewall firewall add rule name="{name}_OUT" dir=out action=block remoteip={ip} enable=yes'

        success_in = self.run_firewall_command(inbound)
        success_out = self.run_firewall_command(outbound)

        if success_in and success_out:
            self.update_status(f"✔ Successfully blocked {ip} in both directions", '#2ecc71')
            messagebox.showinfo("Success", f"Successfully blocked {ip}\n\nInbound and outbound traffic has been blocked.")
        else:
            self.update_status(f"✖ Failed to block {ip}", '#e74c3c')
            messagebox.showerror("Error", f"Failed to completely block {ip}\n\nCheck your firewall settings.")
        
        self.block_btn.config(state='normal', bg='#e74c3c')
        self.unblock_btn.config(state='normal', bg='#27ae60')
        self.block_selected_btn.config(state='normal', bg='#3498db')
    
    def block_selected_connection(self):
        selected = self.tree.selection()
        if not selected:
            self.update_status("✖ Error: No connection selected", '#e74c3c')
            messagebox.showwarning("Selection Error", "Please select a connection from the list to block.")
            return
        
        item = self.tree.item(selected[0])
        foreign_addr = item['values'][2]  
        
        # Extract IP from foreign address (format: IP:PORT)
        ip = foreign_addr.split(':')[0]
        
        if not self.is_ip(ip):
            self.update_status(f"✖ Error: Invalid IP in selected connection", '#e74c3c')
            messagebox.showerror("Error", f"Could not extract valid IP from: {foreign_addr}")
            return
        
        self.entry.delete(0, tk.END)
        self.entry.insert(0, ip)
        self.block_connection()
    
    def unblock_connection(self):
        target = self.entry.get().strip()
        if not target:
            self.update_status("✖ Error: Please enter an IP address or domain", '#e74c3c')
            messagebox.showwarning("Input Error", "Please enter an IP address or domain name to unblock.")
            return

        if not self.is_ip(target):
            self.update_status(f"⌛ Resolving domain: {target}...", '#f1c40f')
            ip = self.resolve_domain(target)
            if ip is None:
                self.update_status(f"✖ Error: Failed to resolve {target}", '#e74c3c')
                messagebox.showerror("DNS Error", f"Failed to resolve domain: {target}")
                return
        else:
            ip = target

        self.update_status(f"⚔ Unblocking {ip}...", '#f1c40f')
        self.block_btn.config(state='disabled', bg='#95a5a6')
        self.unblock_btn.config(state='disabled', bg='#95a5a6')
        self.block_selected_btn.config(state='disabled', bg='#95a5a6')
        self.root.update_idletasks()
        
        name = f"Block_{ip.replace('.', '_')}"
        remove_in = f'netsh advfirewall firewall delete rule name="{name}_IN"'
        remove_out = f'netsh advfirewall firewall delete rule name="{name}_OUT"'
        
        self.run_firewall_command(remove_in)
        self.run_firewall_command(remove_out)
        
        self.update_status(f"✔ Successfully unblocked {ip} in both directions", '#2ecc71')
        messagebox.showinfo("Success", f"Successfully unblocked {ip}\n\nInbound and outbound traffic has been restored.")
        
        self.block_btn.config(state='normal', bg='#e74c3c')
        self.unblock_btn.config(state='normal', bg='#27ae60')
        self.block_selected_btn.config(state='normal', bg='#3498db')

def main():
    # Elevate if not admin
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit()
    
    root = tk.Tk()
    app = UniqueFirewallBlocker(root)
    root.mainloop()

if __name__ == "__main__":
    main()
