import socket
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
from datetime import datetime
import hashlib

from crypto_utils import (
    derive_room_key,
    encrypt_message,
    decrypt_message,
    is_strong_room_code,
)
from biometric_real import require_biometric_auth

HOST = "127.0.0.1"
PORT = 5555


class SecureChatClient:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Biometric Chat")
        self.master.geometry("1100x720")  # larger default window
        self.master.resizable(True, True)

        # ----- State -----
        self.locked = False
        self.running = False
        self.username = None
        self.peers = set()
        self.send_counter = 0
        self.recv_highwater = {}  # sender -> highest counter accepted

        # ----- Colors (dark chat style) -----
        self.bg_main = "#020817"
        self.bg_header = "#111827"
        self.bg_input = "#111827"
        self.color_text = "#e5e7eb"
        self.color_subtle = "#9ca3af"
        self.color_system = "#6b7280"
        self.bubble_in = "#374151"     # incoming
        self.bubble_out = "#22c55e"    # outgoing
        self.bubble_out_text = "#020817"

        # ================= 1. Biometric auth =================
        try:
            require_biometric_auth()
        except PermissionError as e:
            messagebox.showerror("Authentication Failed", str(e))
            master.destroy()
            return

        # ================= 2. Room code -> key (enforce strength) =================
        while True:
            room = simpledialog.askstring(
                "Secure Room",
                "Enter secure room code (use 4+ words OR 16+ mixed chars):",
                parent=self.master
            )
            if not room:
                continue
            if is_strong_room_code(room):
                self.room_code = room
                break
            messagebox.showwarning(
                "Weak Room Code",
                "Please use a stronger room code:\n• 4+ random words (e.g., 'orbit maple glass dial')\n"
                "  OR\n• 16+ characters with a mix of cases/digits."
            )

        try:
            self.room_key = derive_room_key(self.room_code)
        except Exception as e:
            messagebox.showerror("Key Error", f"Failed to derive encryption key: {e}")
            master.destroy()
            return

        self.key_fingerprint = hashlib.sha256(self.room_key).hexdigest()[:12]

        # ================= 3. Connect to server =================
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((HOST, PORT))
        except OSError as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            master.destroy()
            return

        # ================= 4. Username =================
        self.username = simpledialog.askstring(
            "Display Name",
            "Enter your chat display name:",
            parent=self.master
        )
        if not self.username:
            self.username = "User"

        self.peers.add(self.username)
        self.master.title(f"Secure Biometric Chat - {self.username} [{self.room_code}]")

        # ================= 5. UI Layout =================
        self.master.configure(bg=self.bg_main)

        # ----- Header -----
        self.header_frame = tk.Frame(self.master, height=32, bg=self.bg_header)
        self.header_frame.pack(fill=tk.X)

        self.title_label = tk.Label(
            self.header_frame,
            text="Secure Biometric Chat",
            font=("Helvetica", 16, "bold"),
            bg=self.bg_header,
            fg=self.color_text
        )
        self.title_label.pack(side=tk.LEFT, padx=(10, 8))

        self.room_label = tk.Label(
            self.header_frame,
            text=f"Room: {self.room_code}",
            font=("Helvetica", 12),
            bg=self.bg_header,
            fg=self.color_subtle
        )
        self.room_label.pack(side=tk.LEFT)

        self.fp_label = tk.Label(
            self.header_frame,
            text=f"FP: {self.key_fingerprint}",
            font=("Helvetica", 11, "bold"),
            bg=self.bg_header,
            fg="#22c55e"
        )
        self.fp_label.pack(side=tk.RIGHT, padx=(0, 10))

        self.conn_label = tk.Label(
            self.header_frame,
            text=f"{HOST}:{PORT}",
            font=("Helvetica", 11),
            bg=self.bg_header,
            fg="#6b7280"
        )
        self.conn_label.pack(side=tk.RIGHT, padx=(0, 12))

        # ----- Main area (chat left + participants right) -----
        self.main_frame = tk.Frame(self.master, bg=self.bg_main)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 5))

        # Chat container (left, grows)
        self.chat_container = tk.Frame(self.main_frame, bg=self.bg_main)
        self.chat_container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Canvas + scrollbar for bubbles
        self.chat_canvas = tk.Canvas(
            self.chat_container,
            bg=self.bg_main,
            highlightthickness=0,
            bd=0
        )
        self.chat_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.scrollbar = tk.Scrollbar(
            self.chat_container,
            orient="vertical",
            command=self.chat_canvas.yview,
            width=16
        )
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.chat_canvas.configure(yscrollcommand=self.scrollbar.set)

        # Bubbles frame inside canvas
        self.bubble_frame = tk.Frame(self.chat_canvas, bg=self.bg_main)
        self.chat_canvas_window = self.chat_canvas.create_window(
            (0, 0), window=self.bubble_frame, anchor="nw"
        )

        # Update scrollregion on size change
        self.bubble_frame.bind(
            "<Configure>",
            lambda e: self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        )

        # Resize inner frame when window resizes
        self.chat_canvas.bind(
            "<Configure>",
            self._on_canvas_configure
        )

        # Mousewheel scrolling
        self.chat_canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # Participants sidebar (right)
        self.peers_frame = tk.Frame(self.main_frame, bg=self.bg_main, width=160)
        self.peers_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=(10, 0))

        self.peers_label = tk.Label(
            self.peers_frame,
            text="Participants",
            font=("Helvetica", 13, "bold"),
            bg=self.bg_main,
            fg=self.color_text
        )
        self.peers_label.pack(anchor="n", pady=(0, 8))

        self.peers_list = tk.Listbox(
            self.peers_frame,
            height=20,
            borderwidth=0,
            highlightthickness=0,
            bg="#111827",
            fg=self.color_text,
            selectbackground="#374151",
            selectforeground=self.color_text,
            font=("Helvetica", 12)
        )
        self.peers_list.pack(fill=tk.Y, padx=(0, 4), pady=(0, 4))
        self.update_peers_list()

        # ----- Bottom input bar (bigger entry & button) -----
        self.entry_frame = tk.Frame(self.master, bg=self.bg_main)
        self.entry_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.info_button = tk.Button(
            self.entry_frame,
            text="i",
            command=self.show_security_info,
            bg=self.bg_input,
            fg=self.color_subtle,
            activebackground="#1f2937",
            activeforeground=self.color_text,
            bd=0,
            width=3, height=2,
            font=("Helvetica", 12, "bold")
        )
        self.info_button.pack(side=tk.LEFT, padx=(0, 8))

        self.lock_button = tk.Button(
            self.entry_frame,
            text="🔒",
            command=self.toggle_lock,
            bg=self.bg_input,
            fg=self.color_subtle,
            activebackground="#1f2937",
            activeforeground=self.color_text,
            bd=0,
            width=3, height=2,
            font=("Helvetica", 12, "bold")
        )
        self.lock_button.pack(side=tk.LEFT, padx=(0, 8))

        self.clear_button = tk.Button(
            self.entry_frame,
            text="🗑",
            command=self.clear_chat,
            bg=self.bg_input,
            fg=self.color_subtle,
            activebackground="#1f2937",
            activeforeground=self.color_text,
            bd=0,
            width=3, height=2,
            font=("Helvetica", 12, "bold")
        )
        self.clear_button.pack(side=tk.LEFT, padx=(0, 12))

        self.message_entry = tk.Entry(
            self.entry_frame,
            bg=self.bg_input,
            fg=self.color_text,
            insertbackground=self.color_text,
            bd=0,
            relief=tk.FLAT,
            font=("Helvetica", 14)
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 12), ipady=12)
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(
            self.entry_frame,
            text="➤",
            command=self.send_message,
            bg=self.bubble_out,
            fg=self.bubble_out_text,
            activebackground="#16a34a",
            activeforeground=self.bubble_out_text,
            bd=0,
            font=("Helvetica", 16, "bold"),
            width=3, height=2
        )
        self.send_button.pack(side=tk.RIGHT)

        # ----- Status -----
        self.status_label = tk.Label(
            self.master,
            text="Connected · E2E Enabled",
            anchor="w",
            bg=self.bg_main,
            fg="#22c55e",
            font=("Helvetica", 11)
        )
        self.status_label.pack(fill=tk.X, padx=10, pady=(0, 6))

        # ================= 6. Start receiver =================
        self.running = True
        threading.Thread(target=self.receive_loop, daemon=True).start()

        # Initial system messages
        self.add_system_message("Biometric authentication successful. Local device unlocked.")
        self.add_system_message(f"Joined room '{self.room_code}' as {self.username}.")
        self.add_system_message(
            f"Security fingerprint: {self.key_fingerprint} "
            f"(must match on all participants' screens)."
        )

        self.master.protocol("WM_DELETE_WINDOW", self.on_close)

    # ================= Layout / Scroll helpers =================

    def _on_canvas_configure(self, event):
        canvas_width = event.width
        self.chat_canvas.itemconfig(self.chat_canvas_window, width=canvas_width)

    def _on_mousewheel(self, event):
        self.chat_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ================= Participant helpers =================

    def register_peer(self, name: str):
        if not name:
            return
        if name not in self.peers:
            self.peers.add(name)
            self.update_peers_list()

    def update_peers_list(self):
        self.peers_list.delete(0, tk.END)
        for name in sorted(self.peers):
            self.peers_list.insert(tk.END, name)

    # ================= Bubble rendering =================

    def add_system_message(self, text: str):
        row = tk.Frame(self.bubble_frame, bg=self.bg_main)
        row.pack(fill="x", pady=(6, 0))

        label = tk.Label(
            row,
            text=text,
            bg=self.bg_main,
            fg=self.color_system,
            font=("Helvetica", 10, "italic"),
            wraplength=620,
            justify="center"
        )
        label.pack(pady=(0, 2))

        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    def add_message_bubble(self, msg_text: str, ts: str, from_self: bool):
        row = tk.Frame(self.bubble_frame, bg=self.bg_main)
        row.pack(fill="x", pady=6, padx=10)

        if from_self:
            bubble = tk.Frame(row, bg=self.bubble_out, bd=0, padx=14, pady=10)
            bubble.pack(side="right", anchor="e", padx=(80, 0))

            text_label = tk.Label(
                bubble, text=msg_text, bg=self.bubble_out, fg=self.bubble_out_text,
                font=("Helvetica", 13), wraplength=620, justify="left"
            )
            text_label.pack(anchor="w")

            ts_label = tk.Label(
                bubble, text=ts, bg=self.bubble_out, fg="#052e16", font=("Helvetica", 10)
            )
            ts_label.pack(anchor="e", pady=(4, 0))

        else:
            bubble = tk.Frame(row, bg=self.bubble_in, bd=0, padx=14, pady=10)
            bubble.pack(side="left", anchor="w", padx=(0, 80))

            text_label = tk.Label(
                bubble, text=msg_text, bg=self.bubble_in, fg=self.color_text,
                font=("Helvetica", 13), wraplength=620, justify="left"
            )
            text_label.pack(anchor="w")

            ts_label = tk.Label(
                bubble, text=ts, bg=self.bubble_in, fg=self.color_system, font=("Helvetica", 10)
            )
            ts_label.pack(anchor="e", pady=(4, 0))

        self.chat_canvas.update_idletasks()
        self.chat_canvas.yview_moveto(1.0)

    # ================= Sending =================

    def send_message(self, event=None):
        if self.locked:
            messagebox.showwarning("Locked", "Chat is locked. Unlock to send.")
            return

        msg = self.message_entry.get().strip()
        if not msg:
            return

        ts = datetime.now().strftime("%H:%M")
        full_msg = f"[{ts}] {self.username}: {msg}"

        try:
            self.send_counter += 1  # strictly increasing per sender
            token = encrypt_message(self.room_key, self.username, self.send_counter, full_msg)
            self.sock.sendall((token + "\n").encode("utf-8"))
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {e}")
            return

        # Local bubble
        self.add_message_bubble(msg_text=msg, ts=ts, from_self=True)
        self.message_entry.delete(0, tk.END)

    # ================= Receiving =================

    def receive_loop(self):
        buffer = ""
        while self.running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break

                buffer += data.decode("utf-8")
                while "\n" in buffer:
                    token, buffer = buffer.split("\n", 1)
                    token = token.strip()
                    if not token:
                        continue

                    try:
                        sender, counter, plaintext = decrypt_message(self.room_key, token)
                    except Exception:
                        # authentication failed or malformed token
                        continue

                    # Replay protection: enforce strictly increasing per sender
                    last = self.recv_highwater.get(sender, 0)
                    if counter <= last:
                        # drop replay or reordered old message
                        continue
                    self.recv_highwater[sender] = counter

                    # Parse "[HH:MM] name: msg"
                    ts = ""
                    name = sender  # trust AEAD-bound sender
                    msg_body = plaintext
                    try:
                        if plaintext.startswith("[") and "]" in plaintext:
                            closing = plaintext.index("]")
                            ts = plaintext[1:closing]
                            rest = plaintext[closing + 2:]
                            maybe_name, msg_body = rest.split(":", 1)
                            msg_body = msg_body.strip()
                    except ValueError:
                        pass

                    if name == self.username:
                        # Our own echo; we already displayed locally
                        continue

                    if name:
                        self.register_peer(name)

                    self.add_message_bubble(msg_text=msg_body, ts=ts or "", from_self=False)

            except OSError:
                break
            except Exception as e:
                print(f"[!] Receive error: {e}")
                break

        self.status_label.config(text="Disconnected", fg="#ef4444")
        self.add_system_message("Disconnected from server.")

    # ================= UI Actions =================

    def show_security_info(self):
        messagebox.showinfo(
            "Security Design",
            "• Strong KDF: scrypt(room_code) → AES-256 key (harder to brute-force weak codes).\n"
            "• Every message uses a fresh random nonce (AES-GCM).\n"
            "• AEAD header binds sender + counter + nonce → anti-spoof & anti-replay.\n"
            "• Per-sender replay protection (monotonic counters).\n"
            "• Server relays ciphertext only; no plaintext or keys."
        )

    def toggle_lock(self):
        if not self.locked:
            self.locked = True
            self.message_entry.config(state="disabled")
            self.send_button.config(state="disabled")
            self.status_label.config(
                text="Locked · Biometric re-auth required",
                fg="#fbbf24"
            )
            self.lock_button.config(text="🔓")
        else:
            try:
                require_biometric_auth()
            except PermissionError:
                messagebox.showerror("Authentication Failed", "Biometric re-auth failed.")
                return

            self.locked = False
            self.message_entry.config(state="normal")
            self.send_button.config(state="normal")
            self.status_label.config(
                text="Connected · E2E Enabled",
                fg="#22c55e"
            )
            self.lock_button.config(text="🔒")

    def clear_chat(self):
        if messagebox.askyesno("Clear Chat", "Clear all messages from this window?"):
            for widget in self.bubble_frame.winfo_children():
                widget.destroy()
            self.add_system_message("Chat cleared locally (ephemeral mode).")

    # ================= Layout Close =================

    def on_close(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatClient(root)
    root.mainloop()