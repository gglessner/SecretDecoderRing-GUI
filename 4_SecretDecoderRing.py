# SecretDecoderRing - part of the HACKtiveMQ Suite
# Copyright (C) 2025 Garland Glessner - gglesner@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from PySide6.QtWidgets import QWidget, QPlainTextEdit, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QComboBox, QPushButton, QFrame, QGridLayout, QFileDialog, QSpacerItem, QSizePolicy, QTableWidget, QTableWidgetItem, QHeaderView
from PySide6.QtGui import QFont, QFontMetrics
from PySide6.QtCore import Qt
import importlib.util
import os
import re
import base64
import binascii
import csv

# Define the version number at the top
VERSION = "1.3.4"

# Define the tab label for the tab widget
TAB_LABEL = f"SecretDecoderRing v{VERSION}"

class Ui_TabContent:
    def setupUi(self, widget):
        """Set up the UI components for the SecretDecoderRing tab."""
        widget.setObjectName("TabContent")

        # Main vertical layout with reduced spacing
        self.verticalLayout_3 = QVBoxLayout(widget)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.verticalLayout_3.setSpacing(5)

        self.verticalLayout_3.addSpacerItem(QSpacerItem(0, 1, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Header frame with title and input fields
        self.frame_8 = QFrame(widget)
        self.frame_8.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_3 = QHBoxLayout(self.frame_8)
        self.horizontalLayout_3.setContentsMargins(0, 0, 0, 0)

        self.frame_5 = QFrame(self.frame_8)
        self.frame_5.setFrameShape(QFrame.StyledPanel)
        self.horizontalLayout_3.addWidget(self.frame_5)

        self.label_3 = QLabel(self.frame_8)
        font = QFont("Courier New", 14)
        font.setBold(True)
        self.label_3.setFont(font)
        self.label_3.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.horizontalLayout_3.addWidget(self.label_3)

        self.frame_10 = QFrame(self.frame_8)
        self.frame_10.setFrameShape(QFrame.NoFrame)
        self.gridLayout_2 = QGridLayout(self.frame_10)
        self.gridLayout_2.setContentsMargins(0, 0, 0, 0)
        self.gridLayout_2.setVerticalSpacing(0)  # Minimal vertical gap

        # IV/Nonce input frame
        self.frame_11 = QFrame(self.frame_10)
        self.frame_11.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_5 = QHBoxLayout(self.frame_11)
        self.horizontalLayout_5.setContentsMargins(0, 0, 0, 0)

        self.label_5 = QLabel(self.frame_11)
        self.horizontalLayout_5.addWidget(self.label_5)

        self.IVLine = QLineEdit(self.frame_11)
        self.horizontalLayout_5.addWidget(self.IVLine)

        self.IVcomboBox = QComboBox(self.frame_11)
        self.IVcomboBox.addItems(["Base64", "HEX", "ASCII"])
        self.horizontalLayout_5.addWidget(self.IVcomboBox)

        self.gridLayout_2.addWidget(self.frame_11, 0, 0, 1, 1)

        # Key input frame
        self.frame_12 = QFrame(self.frame_10)
        self.frame_12.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_6 = QHBoxLayout(self.frame_12)
        self.horizontalLayout_6.setContentsMargins(0, 0, 0, 0)

        self.label_6 = QLabel(self.frame_12)
        self.horizontalLayout_6.addWidget(self.label_6)

        self.KeyLine = QLineEdit(self.frame_12)
        self.horizontalLayout_6.addWidget(self.KeyLine)

        self.KeycomboBox = QComboBox(self.frame_12)
        self.KeycomboBox.addItems(["Base64", "HEX", "ASCII"])
        self.horizontalLayout_6.addWidget(self.KeycomboBox)

        self.gridLayout_2.addWidget(self.frame_12, 1, 0, 1, 1)

        self.horizontalLayout_3.addWidget(self.frame_10)
        self.verticalLayout_3.addWidget(self.frame_8)

        self.verticalLayout_3.addSpacerItem(QSpacerItem(0, 1, QSizePolicy.Minimum, QSizePolicy.Fixed))

        # Main content frame
        self.frame_3 = QFrame(widget)
        self.gridLayout = QGridLayout(self.frame_3)
        self.gridLayout.setContentsMargins(0, 0, 0, 0)

        # Cipher text controls
        self.frame = QFrame(self.frame_3)
        self.frame.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout = QHBoxLayout(self.frame)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)

        self.label = QLabel(self.frame)
        self.horizontalLayout.addWidget(self.label)

        self.CipherTextcomboBox = QComboBox(self.frame)
        self.CipherTextcomboBox.addItems(["Base64", "HEX", "ASCII"])
        self.horizontalLayout.addWidget(self.CipherTextcomboBox)

        self.CipherTextClearButton = QPushButton(self.frame)
        self.CipherTextClearButton.setText("Clear")
        self.horizontalLayout.addWidget(self.CipherTextClearButton)

        self.CipherTextLoadButton = QPushButton(self.frame)
        self.horizontalLayout.addWidget(self.CipherTextLoadButton)

        self.CipherTextSaveButton = QPushButton(self.frame)
        self.CipherTextSaveButton.setText("Save")
        self.horizontalLayout.addWidget(self.CipherTextSaveButton)

        self.CipherTextSortDedupButton = QPushButton(self.frame)
        self.CipherTextSortDedupButton.setText("Sort+Dedup")
        self.horizontalLayout.addWidget(self.CipherTextSortDedupButton)

        self.horizontalSpacer_3 = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.horizontalLayout.addItem(self.horizontalSpacer_3)

        self.gridLayout.addWidget(self.frame, 0, 0, 1, 1)

        # Plain text controls
        self.frame_2 = QFrame(self.frame_3)
        self.frame_2.setFrameShape(QFrame.NoFrame)
        self.horizontalLayout_2 = QHBoxLayout(self.frame_2)
        self.horizontalLayout_2.setContentsMargins(0, 0, 0, 0)

        self.label_2 = QLabel(self.frame_2)
        self.horizontalLayout_2.addWidget(self.label_2)

        self.PlainTextClearButton = QPushButton(self.frame_2)
        self.PlainTextClearButton.setText("Clear")
        self.horizontalLayout_2.addWidget(self.PlainTextClearButton)

        self.PlainTextSaveButton = QPushButton(self.frame_2)
        self.PlainTextSaveButton.setText("Save")
        self.horizontalLayout_2.addWidget(self.PlainTextSaveButton)

        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(self.horizontalSpacer)

        self.DecryptButton = QPushButton(self.frame_2)
        font1 = QFont()
        font1.setBold(True)
        self.DecryptButton.setFont(font1)
        self.horizontalLayout_2.addWidget(self.DecryptButton)

        self.gridLayout.addWidget(self.frame_2, 0, 1, 1, 1)

        # Text boxes
        self.CipherTextBox = QPlainTextEdit(self.frame_3)
        self.gridLayout.addWidget(self.CipherTextBox, 1, 0, 1, 1)

        # Plaintext table
        self.PlainTextTable = QTableWidget(self.frame_3)
        self.PlainTextTable.setColumnCount(6)
        self.PlainTextTable.setHorizontalHeaderLabels(["Ciphertext", "Plaintext", "Algorithm", "Mode", "Key", "IV/Nonce"])
        self.PlainTextTable.setEditTriggers(QTableWidget.NoEditTriggers)  # Make read-only
        self.PlainTextTable.setSortingEnabled(True)  # Enable sorting
        self.gridLayout.addWidget(self.PlainTextTable, 1, 1, 1, 1)

        # Adjust column widths in the grid layout
        self.gridLayout.setColumnStretch(0, 3)  # CipherTextBox: 3 parts
        self.gridLayout.setColumnStretch(1, 5)  # PlainTextTable: 5 parts

        self.verticalLayout_3.addWidget(self.frame_3)

        # Status frame
        self.frame_4 = QFrame(widget)
        self.frame_4.setFrameShape(QFrame.NoFrame)
        self.verticalLayout = QVBoxLayout(self.frame_4)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)

        self.StatusTextBox = QPlainTextEdit(self.frame_4)
        self.StatusTextBox.setReadOnly(True)
        self.verticalLayout.addWidget(self.StatusTextBox)

        self.verticalLayout_3.addWidget(self.frame_4)

        # Adjust spacing
        self.gridLayout.setVerticalSpacing(0)
        self.horizontalLayout.setSpacing(0)
        self.horizontalLayout_2.setSpacing(0)

        self.retranslateUi(widget)

    def retranslateUi(self, widget):
        self.label_3.setText(f"""
  __                  _                         _            
 (_   _   _ ._ _ _|_ | \\  _   _  _   _|  _  ._ |_) o ._   _  
 __) (/_ (_ | (/_ |_ |_/ (/_ (_ (_) (_| (/_ |  | \\ | | | (_|
                                                          _|
 Version: {VERSION}""")
        self.label_5.setText("IV/Nonce:")
        self.label_6.setText("Key:")
        self.label.setText("CipherText:  ")
        self.CipherTextLoadButton.setText("Load")
        self.CipherTextSaveButton.setText("Save")
        self.label_2.setText("PlainText:  ")
        self.PlainTextSaveButton.setText("Save")
        self.PlainTextClearButton.setText("Clear")
        self.DecryptButton.setText("Decrypt")

class TabContent(QWidget):
    def __init__(self):
        """Initialize the TabContent widget with custom adjustments."""
        super().__init__()
        self.ui = Ui_TabContent()
        self.ui.setupUi(self)

        # Initialize encryption modules
        self.modules = []
        self.load_encryption_modules()

        # Set IVLine and KeyLine to exactly 32 characters wide
        font_metrics = QFontMetrics(self.ui.IVLine.font())
        char_width = font_metrics.averageCharWidth()
        width_32_chars = char_width * 32
        self.ui.IVLine.setFixedWidth(width_32_chars)
        self.ui.KeyLine.setFixedWidth(width_32_chars)

        # Additional UI adjustments
        self.ui.KeycomboBox.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.ui.IVcomboBox.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.ui.CipherTextcomboBox.setSizeAdjustPolicy(QComboBox.AdjustToContents)

        spacer_iv = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ui.horizontalLayout_5.insertSpacerItem(0, spacer_iv)

        spacer_key = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.ui.horizontalLayout_6.insertSpacerItem(0, spacer_key)

        self.ui.CipherTextLoadButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.CipherTextSaveButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.CipherTextClearButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.CipherTextSortDedupButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.PlainTextSaveButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.PlainTextClearButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ui.DecryptButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        # Initialize PlainTextTable
        self.ui.PlainTextTable.setRowCount(0)
        self.ui.PlainTextTable.setStyleSheet("""
            QHeaderView::section:horizontal {
                border: 1px solid black;
                padding: 4px;
            }
        """)
        # Set column widths
        self.ui.PlainTextTable.setColumnWidth(0, 150)  # Ciphertext
        self.ui.PlainTextTable.setColumnWidth(1, 150)  # Plaintext
        self.ui.PlainTextTable.setColumnWidth(2, 100)  # Algorithm
        self.ui.PlainTextTable.setColumnWidth(3, 80)   # Mode
        self.ui.PlainTextTable.setColumnWidth(4, 150)  # Key
        self.ui.PlainTextTable.setColumnWidth(5, 150)  # IV/Nonce

        # Connect signals to slots
        self.ui.CipherTextLoadButton.clicked.connect(self.load_ciphertext)
        self.ui.CipherTextSaveButton.clicked.connect(self.save_ciphertext)
        self.ui.CipherTextClearButton.clicked.connect(self.clear_ciphertext)
        self.ui.CipherTextSortDedupButton.clicked.connect(self.sort_dedup_ciphertext)
        self.ui.PlainTextSaveButton.clicked.connect(self.save_plaintext)
        self.ui.PlainTextClearButton.clicked.connect(self.clear_plaintext)
        self.ui.DecryptButton.clicked.connect(self.decrypt)
        self.ui.KeyLine.returnPressed.connect(self.decrypt)

    def showEvent(self, event):
        """Override the showEvent to set focus to the KeyLine when the tab is shown."""
        super().showEvent(event)
        self.ui.KeyLine.setFocus()

    def load_encryption_modules(self):
        """Load all encryption modules from the modules/SecretDecoderRing_modules directory."""
        modules_dir = os.path.join('modules', 'SecretDecoderRing_modules')
        if os.path.isdir(modules_dir):
            for filename in os.listdir(modules_dir):
                if filename.endswith('.py') and filename != '__init__.py':
                    module_name = filename[:-3]
                    file_path = os.path.join(modules_dir, filename)
                    spec = importlib.util.spec_from_file_location(module_name, file_path)
                    if spec is None:
                        self.ui.StatusTextBox.appendPlainText(f"Error: Could not create spec for {filename}")
                        continue
                    module = importlib.util.module_from_spec(spec)
                    try:
                        spec.loader.exec_module(module)
                        if hasattr(module, 'decrypt'):
                            self.modules.append(module)
                        else:
                            self.ui.StatusTextBox.appendPlainText(f"Warning: {filename} does not have a 'decrypt' function")
                    except Exception as e:
                        self.ui.StatusTextBox.appendPlainText(f"Error loading {filename}: {e}")
        else:
            self.ui.StatusTextBox.appendPlainText(f"Error: Directory '{modules_dir}' not found")
        if not self.modules:
            self.ui.StatusTextBox.appendPlainText("No encryption modules found")
        else:
            self.ui.StatusTextBox.appendPlainText(f"Loaded {len(self.modules)} encryption modules: {[m.__name__ for m in self.modules]}")

    def process_input(self, input_str, format_type, input_type="data"):
        """Process input string based on selected format (Base64, HEX, ASCII)."""
        if not input_str and input_type == "iv":
            return b'\x00' * 16, None  # Default null IV
        if not input_str:
            raise ValueError("Input cannot be empty")

        if format_type == "HEX":
            input_str = input_str.strip()
            if input_str.startswith('0x'):
                input_str = input_str[2:]
            if not re.match(r'^[0-9a-fA-F]+$', input_str):
                raise ValueError("Invalid hex characters")
            try:
                return bytes.fromhex(input_str), None
            except ValueError as e:
                raise ValueError(f"Invalid hex input: {e}")

        elif format_type == "Base64":
            try:
                result = base64.b64decode(input_str, validate=True)
                note = None
                if input_type == "ciphertext":
                    try:
                        utf8_decoded = result.decode('utf-8')
                        note = f"NOTE - Base64-decoded ciphertext is a valid UTF-8 string: '{utf8_decoded}'"
                    except UnicodeDecodeError:
                        pass
                return result, note
            except binascii.Error as e:
                raise ValueError(f"Invalid base64 input: {e}")

        elif format_type == "ASCII":
            return input_str.encode('utf-8'), None

        else:
            raise ValueError(f"Unknown format: {format_type}")

    def load_ciphertext(self):
        """Load cipher text from a file into the CipherTextBox."""
        file_name, _ = QFileDialog.getOpenFileName(self, "Load Cipher Text", "", "All Files (*);;Text Files (*.txt)")
        if file_name:
            try:
                with open(file_name, 'r', encoding='utf-8') as f:
                    self.ui.CipherTextBox.setPlainText(f.read())
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error loading file: {e}")

    def save_ciphertext(self):
        """Save the contents of the CipherTextBox to a file."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Cipher Text", "", "All Files (*);;Text Files (*.txt)")
        if file_name:
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(self.ui.CipherTextBox.toPlainText())
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error saving file: {e}")

    def clear_ciphertext(self):
        """Clear the contents of the CipherTextBox."""
        self.ui.CipherTextBox.clear()

    def sort_dedup_ciphertext(self):
        """Sort and deduplicate the lines in the CipherTextBox."""
        # Get current ciphertext lines
        ciphertexts = [c.strip() for c in self.ui.CipherTextBox.toPlainText().splitlines() if c.strip()]
        if not ciphertexts:
            self.ui.StatusTextBox.appendPlainText("\nNo ciphertext lines to sort or deduplicate.")
            return

        # Sort and deduplicate
        unique_ciphertexts = sorted(set(ciphertexts))

        # Join back into text
        sorted_text = '\n'.join(unique_ciphertexts)
        self.ui.CipherTextBox.setPlainText(sorted_text)
        self.ui.StatusTextBox.appendPlainText(f"\nSorted and deduplicated {len(ciphertexts)} ciphertext lines to {len(unique_ciphertexts)} unique lines.")

    def save_plaintext(self):
        """Save the contents of the PlainTextTable to a CSV file."""
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Plain Text", "", "CSV Files (*.csv);;All Files (*)")
        if file_name:
            # Ensure the file has a .csv extension
            if not file_name.lower().endswith('.csv'):
                file_name += '.csv'
            try:
                with open(file_name, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                    # Write header
                    header = ["Ciphertext", "Plaintext", "Algorithm", "Mode", "Key", "IV/Nonce"]
                    writer.writerow(header)
                    # Write table rows
                    for row in range(self.ui.PlainTextTable.rowCount()):
                        row_data = []
                        for col in range(self.ui.PlainTextTable.columnCount()):
                            item = self.ui.PlainTextTable.item(row, col)
                            row_data.append(item.text() if item else "")
                        writer.writerow(row_data)
                self.ui.StatusTextBox.appendPlainText(f"\nPlaintext saved to {file_name}")
            except Exception as e:
                self.ui.StatusTextBox.appendPlainText(f"Error saving file: {e}")

    def clear_plaintext(self):
        """Clear the contents of the PlainTextTable."""
        self.ui.PlainTextTable.setRowCount(0)

    def is_typeable_ascii(self, text):
        """Check if the text contains only printable ASCII characters (32-126)."""
        return all(32 <= ord(char) <= 126 for char in text)

    def decrypt(self):
        """Process ciphertexts from CipherTextBox and attempt decryption."""
        if not self.modules:
            self.ui.StatusTextBox.appendPlainText("No encryption modules loaded. Cannot decrypt.")
            return

        # Get IV
        iv_input = self.ui.IVLine.text().strip()
        iv_format = self.ui.IVcomboBox.currentText()
        try:
            iv, _ = self.process_input(iv_input, iv_format, "iv")
            self.ui.StatusTextBox.appendPlainText(f"\nIV (hex): {iv.hex()} ({len(iv)} bytes)")
        except ValueError as e:
            self.ui.StatusTextBox.appendPlainText(f"Error processing IV: {e}")
            return

        # Get Key
        key_input = self.ui.KeyLine.text().strip()
        key_format = self.ui.KeycomboBox.currentText()
        try:
            key, _ = self.process_input(key_input, key_format, "key")
            self.ui.StatusTextBox.appendPlainText(f"Key (hex): {key.hex()} ({len(key)} bytes)")
        except ValueError as e:
            self.ui.StatusTextBox.appendPlainText(f"Error processing Key: {e}")
            return

        # Get Ciphertexts
        ciphertexts = self.ui.CipherTextBox.toPlainText().splitlines()
        cipher_format = self.ui.CipherTextcomboBox.currentText()

        # Clear existing table content
        self.ui.PlainTextTable.setRowCount(0)

        for idx, ciphertext_input in enumerate(ciphertexts, 1):
            ciphertext_input = ciphertext_input.strip()
            if not ciphertext_input:
                continue

            self.ui.StatusTextBox.appendPlainText(f"\nProcessing ciphertext {idx}: {ciphertext_input}")
            try:
                ciphertext, note = self.process_input(ciphertext_input, cipher_format, "ciphertext")
                self.ui.StatusTextBox.appendPlainText(f"Ciphertext (hex): {ciphertext.hex()} ({len(ciphertext)} bytes)")
                if note:
                    self.ui.StatusTextBox.appendPlainText(note)

                self.ui.StatusTextBox.appendPlainText("\nAttempting decryption with each module...\n")
                success = False
                for module in self.modules:
                    try:
                        results = module.decrypt(iv, key, ciphertext)
                        if results:
                            for mode, plaintext in results:
                                mode_str = mode if mode else "N/A"
                                try:
                                    decoded = plaintext.decode('utf-8')
                                    if self.is_typeable_ascii(decoded):
                                        self.ui.StatusTextBox.appendPlainText(
                                            f"Decryption succeeded with {module.__name__} in {mode_str} mode: {decoded} [{ciphertext_input}]"
                                        )
                                        # Add row to PlainTextTable
                                        row_count = self.ui.PlainTextTable.rowCount()
                                        self.ui.PlainTextTable.insertRow(row_count)
                                        row_data = [
                                            ciphertext_input,           # Ciphertext
                                            decoded,                    # Plaintext
                                            module.__name__,            # Algorithm
                                            mode_str,                   # Mode
                                            key_input,                  # Key
                                            iv_input                    # IV/Nonce
                                        ]
                                        for col, data in enumerate(row_data):
                                            item = QTableWidgetItem(str(data))
                                            item.setFlags(item.flags() & ~Qt.ItemIsEditable)  # Make cell read-only
                                            item.setTextAlignment(Qt.AlignCenter)
                                            self.ui.PlainTextTable.setItem(row_count, col, item)
                                        success = True
                                    else:
                                        self.ui.StatusTextBox.appendPlainText(
                                            f"Decryption with {module.__name__} in {mode_str} mode produced non-typeable ASCII: {decoded} [{ciphertext_input}]"
                                        )
                                except UnicodeDecodeError:
                                    self.ui.StatusTextBox.appendPlainText(
                                        f"Decryption with {module.__name__} in {mode_str} mode resulted in non-UTF-8 output."
                                    )
                        else:
                            self.ui.StatusTextBox.appendPlainText(
                                f"Decryption failed with {module.__name__}: No successful decryption"
                            )
                    except Exception as e:
                        self.ui.StatusTextBox.appendPlainText(f"Error in {module.__name__}: {e}")
                if not success:
                    self.ui.StatusTextBox.appendPlainText("No module could decrypt the ciphertext with typeable ASCII output.")
            except ValueError as e:
                self.ui.StatusTextBox.appendPlainText(f"Error processing ciphertext: {e}")
