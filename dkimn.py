import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
from tkinter import filedialog
import dns.resolver
import threading
import re
import os
import logging
from datetime import datetime
import dns.exception
import sys

from email.parser import BytesParser
from email import policy

class DKIMRecordAnalyzer:

    @staticmethod
    def validate_dkim_record_structure(record):
        """
        Validate basic DKIM record structure
        """
        required_checks = [
            'v=DKIM1' in record,  # Version check
            'k=' in record,       # Key type
            'p=' in record        # Public key
        ]
        return all(required_checks)

    @staticmethod
    def discover_selectors(domain, suppress_output=False):
        """
        Discover DKIM selectors dynamically by testing common patterns.
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        base_selectors = [
            'default', 'google', 'selector', 's', 'k', 'dkim', 'email', 'smtp', 'mail'
        ]
        discovered_selectors = []

        for base in base_selectors:
            for i in range(1, 6):  # Test numeric suffixes (e.g., selector1, s2)
                selector = f"{base}{i}"
                query_name = f"{selector}._domainkey.{domain}"
                try:
                    if not suppress_output:
                        print(f"Testing selector: {query_name}")
                    resolver.resolve(query_name, 'TXT')
                    discovered_selectors.append(selector)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
                except dns.exception.Timeout:
                    if not suppress_output:
                        print(f"Timeout while testing selector: {query_name}")
                except Exception as e:
                    if not suppress_output:
                        print(f"Error testing selector {selector}: {e}")

        return discovered_selectors




    @staticmethod
    def validate_domain(domain):
        """
        Validate domain format using a comprehensive regex
        """
        domain_regex = re.compile(
            r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$', 
            re.IGNORECASE
        )
        return domain_regex.match(domain) is not None


    @staticmethod
    def extract_dkim_records(domain, selectors=None):
        """
        Extract DKIM records with dynamic selector discovery.
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10

        # Discover additional selectors dynamically
        dynamic_selectors = DKIMRecordAnalyzer.discover_selectors(domain, suppress_output=True)

        # Merge predefined selectors with dynamically discovered selectors
        if not selectors:
            selectors = [
                'default', 'selector1', 'selector2',
                's1', 's2', 'k1', 'dkim', 'email', 'smtp', 'mail',
                '20161025'
            ] + dynamic_selectors

        # Common subdomains for DKIM records
        subdomains = [domain, f"mail.{domain}", f"email.{domain}", f"smtp.{domain}", f"dkim.{domain}"]

        records_info = []
        seen_records = set()  # Set to track unique records

        for subdomain in subdomains:
            for selector in selectors:
                query_name = f"{selector}._domainkey.{subdomain}"
                try:
                    # Resolve TXT records
                    print(f"Querying: {query_name}")  # Debugging output
                    dkim_records = resolver.resolve(query_name, 'TXT')

                    for record in dkim_records:
                        record_text = record.to_text().strip('"')

                        # Validate DKIM record structure
                        if DKIMRecordAnalyzer.validate_dkim_record_structure(record_text):
                            # Create a hashable representation of the record
                            record_hash = (selector, subdomain, record_text)

                            if record_hash not in seen_records:
                                seen_records.add(record_hash)  # Add to seen records
                                parsed_record = DKIMRecordAnalyzer._parse_dkim_record(record_text)
                                parsed_record['selector'] = selector
                                parsed_record['subdomain'] = subdomain

                                records_info.append(parsed_record)

                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    # This selector doesn't exist, continue to next
                    continue
                except dns.exception.Timeout:
                    print(f"Timeout for query: {query_name}")
                except Exception as e:
                    print(f"Error with query {query_name}: {e}")

        return {
            'domain': domain,
            'records': records_info,
            'dynamic_selectors': dynamic_selectors,
            'status': 'Analysis completed' if records_info else 'No records found'
        }


    @staticmethod
    def validate_domain(domain):
        """
        Valida il formato del dominio usando una regex completa
        """
        import re
        domain_regex = re.compile(
            r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$', 
            re.IGNORECASE
        )
        return domain_regex.match(domain) is not None

    @staticmethod
    def perform_advanced_dkim_validation(record_dict):
        """
        Perform comprehensive DKIM record validation and security checks
        """
        validation_results = {
            'is_valid': True,
            'warnings': [],
            'errors': [],
            'security_level': 'HIGH'
        }

        # Required fields validation
        required_fields = {
            'v': 'DKIM version',
            'p': 'Public key',
            'k': 'Key type'
        }

        for field, description in required_fields.items():
            if field not in record_dict:
                validation_results['is_valid'] = False
                validation_results['errors'].append(f"Missing required field: {description} ({field})")

        # Version validation
        if record_dict.get('v') != 'DKIM1':
            validation_results['is_valid'] = False
            validation_results['errors'].append("Invalid DKIM version. Must be 'DKIM1'")

        # Key type validation
        valid_key_types = ['rsa', 'ed25519']
        key_type = record_dict.get('k', '').lower()
        if key_type not in valid_key_types:
            validation_results['is_valid'] = False
            validation_results['errors'].append(f"Invalid key type. Must be one of: {', '.join(valid_key_types)}")

        # Public key validation
        if 'p' in record_dict:
            # Check if key is empty
            if not record_dict['p']:
                validation_results['is_valid'] = False
                validation_results['errors'].append("Empty public key")
            else:
                # Estimate key length (assuming RSA)
                key_length = len(record_dict['p']) * 3 / 4 * 8  # Approximate bit length for base64
                
                if key_length < 1024:
                    validation_results['security_level'] = 'LOW'
                    validation_results['warnings'].append(
                        f"Weak key length ({int(key_length)} bits). Recommended minimum is 2048 bits"
                    )
                elif key_length < 2048:
                    validation_results['security_level'] = 'MEDIUM'
                    validation_results['warnings'].append(
                        f"Moderate key length ({int(key_length)} bits). Consider upgrading to 2048 bits or higher"
                    )

        # Optional field validations
        if 't' in record_dict:
            flags = record_dict['t'].split(':')
            valid_flags = ['y', 's']
            invalid_flags = [f for f in flags if f not in valid_flags]
            if invalid_flags:
                validation_results['warnings'].append(
                    f"Unknown flags in 't' tag: {', '.join(invalid_flags)}"
                )

        # Hash algorithm validation
        if 'h' in record_dict:
            hash_algorithms = record_dict['h'].split(':')
            valid_algorithms = ['sha256', 'sha1']
            invalid_algorithms = [h for h in hash_algorithms if h not in valid_algorithms]
            if invalid_algorithms:
                validation_results['warnings'].append(
                    f"Unsupported hash algorithms: {', '.join(invalid_algorithms)}"
                )

        # Notes field
        if 'n' in record_dict:
            validation_results['warnings'].append(
                f"Notes field (n=) found: {record_dict['n']}"
            )

        # Service type validation
        if 's' in record_dict:
            services = record_dict['s'].split(':')
            valid_services = ['*', 'email']
            invalid_services = [s for s in services if s not in valid_services]
            if invalid_services:
                validation_results['warnings'].append(
                    f"Unknown service types: {', '.join(invalid_services)}"
                )

        return validation_results

    @staticmethod
    def _parse_dkim_record(record):
        """
        Enhanced parse DKIM record and extract fields with validation
        """
        dkim_info = {'raw_record': record}
        parts = record.split(';')
        
        for part in parts:
            part = part.strip()
            if '=' in part:
                key, value = part.split('=', 1)
                key = key.strip()
                value = value.strip()
                if key == 'p':
                    value = ''.join(value.split())  # Remove internal whitespaces
                dkim_info[key] = value

        # Perform advanced validation
        validation_results = DKIMRecordAnalyzer.perform_advanced_dkim_validation(dkim_info)
        dkim_info['validation_results'] = validation_results

        return dkim_info


class DKIMExtractorGUI:
    def __init__(self, root):

    

        self.root = root
        self.root.title("Advanced Multi-Domain DKIM Record Extractor")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')

        # Logging 
        
        self._setup_logging()
        
        # Create UI
        self._create_widgets()

    def _setup_logging(self):
                """
                Configure logging for the GUI application.
                """
                self.logger, self.results_filename = setup_logging_and_results(is_cli=False)


    def setup_logging_and_results(is_cli=False):
        """
        Configure logging and results file.
        If is_cli is True, the filenames are adjusted for CLI use.
        """
        log_dir = "logs"
        results_dir = "results"
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(results_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        prefix = "cli" if is_cli else "gui"
        log_filename = os.path.join(log_dir, f"{prefix}_log_{timestamp}.log")
        results_filename = os.path.join(results_dir, f"{prefix}_results_{timestamp}.txt")

        logging.basicConfig(
            filename=log_filename,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s: %(message)s'
        )
        logger = logging.getLogger(__name__)

        return logger, results_filename


    def _create_widgets(self):
        """
        Create GUI widgets with multi-line domain input
        """
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Domain input (now using Text widget for multiple lines)
        input_label = ttk.Label(main_frame, text="Enter Domains (one per line):")
        input_label.pack(anchor='w')

        self.domain_text = scrolledtext.ScrolledText(main_frame, width=70, height=5)
        self.domain_text.pack(fill=tk.X, expand=True, pady=5)

        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=5)

        analyze_button = ttk.Button(
            button_frame, 
            text="Analyze Domains", 
            command=self._start_analysis
        )
        analyze_button.pack(side=tk.LEFT, padx=5)

        custom_selector_button = ttk.Button(
            button_frame, 
            text="Custom Selectors", 
            command=self._get_custom_selectors
        )
        custom_selector_button.pack(side=tk.LEFT, padx=5)

        clear_button = ttk.Button(
            button_frame, 
            text="Clear", 
            command=self._clear_results
        )
        clear_button.pack(side=tk.LEFT, padx=5)

        # Progress frame
        self.progress_frame = ttk.Frame(main_frame)
        self.progress_frame.pack(fill=tk.X, pady=5)
        
        self.progress_label = ttk.Label(self.progress_frame, text="")
        self.progress_label.pack(side=tk.LEFT)

        # Results area
        result_label = ttk.Label(main_frame, text="Analysis Results:")
        result_label.pack(anchor='w')

        self.result_text = scrolledtext.ScrolledText(
            main_frame, 
            wrap=tk.WORD, 
            width=100, 
            height=25,
            font=('Courier', 10)
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)
        email_button = ttk.Button(
        button_frame, 
        text="Analyze Email", 
        command=self._analyze_email
    )
        email_button.pack(side=tk.LEFT, padx=5)

    def _analyze_email(self):
        """
        Analyze a single email for DKIM signatures.
        """
        email_path = filedialog.askopenfilename(
            title="Select Email File",
            filetypes=[("Email Files", "*.eml"), ("All Files", "*.*")]
        )
        if not email_path:
            return

        try:
            with open(email_path, 'rb') as f:
                email_content = f.read()

            results = EmailDKIMVerifier.verify_email_dkim(email_content)

            with open(self.results_filename, 'a', encoding='utf-8') as results_file:
                results_file.write("=" * 60 + "\n")
                results_file.write(f"Email File: {email_path}\n")
                results_file.write("=" * 60 + "\n")

                for result in results:
                    # Log results to file
                    results_file.write(f"Status: {result['status']}\n")
                    results_file.write(f"Message: {result['message']}\n")
                    if 'record' in result:
                        results_file.write(f"Record: {result['record']}\n")
                    results_file.write("-" * 60 + "\n")

                    # Display results in GUI
                    self.result_text.insert(tk.END, f"Status: {result['status']}\n")
                    self.result_text.insert(tk.END, f"Message: {result['message']}\n")
                    if 'record' in result:
                        self.result_text.insert(tk.END, f"Record: {result['record']}\n")
                    self.result_text.insert(tk.END, "-" * 60 + "\n")

            # Log completion
            self.logger.info(f"Analysis completed for email: {email_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze email: {e}")
            self.logger.error(f"Error analyzing email {email_path}: {e}")


    def _start_analysis(self):
        """
        Start analysis for multiple domains
        """
        # Get domains from text widget
        domains_text = self.domain_text.get(1.0, tk.END).strip()
        domains = [d.strip() for d in domains_text.split('\n') if d.strip()]

        # Validate domains
        invalid_domains = []
        valid_domains = []
        for domain in domains:
            if DKIMRecordAnalyzer.validate_domain(domain):
                valid_domains.append(domain)
            else:
                invalid_domains.append(domain)

        if invalid_domains:
            messagebox.showerror("Invalid Domains", 
                               f"The following domains are not valid:\n{', '.join(invalid_domains)}")
            return

        if not valid_domains:
            messagebox.showerror("No Domains", "Please enter at least one valid domain.")
            return

        # Clear previous results
        self.result_text.delete(1.0, tk.END)
        
        # Get custom selectors
        selectors = getattr(self, 'custom_selectors', None)

        # Start analysis in a separate thread
        threading.Thread(
            target=self._perform_multi_domain_analysis,
            args=(valid_domains, selectors),
            daemon=True
        ).start()

    def _perform_analysis(self, domain, selectors=None):
        """
        Perform detailed DKIM record analysis for a single domain and display results in the GUI.
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8"]  # Usa il resolver pubblico di Google per evitare reindirizzamenti

            try:
                resolver.resolve(domain, 'A')  # Prova a risolvere il dominio
            except dns.resolver.NXDOMAIN:
                self.result_text.insert(tk.END, f"❌ ERROR: Domain '{domain}' does not exist.\n")
                self.result_text.insert(tk.END, "-" * 60 + "\n\n")
                return  # Esce senza procedere con l'analisi
            except (dns.resolver.NoAnswer, dns.exception.Timeout):
                self.result_text.insert(tk.END, f"⚠️ WARNING: Unable to verify existence of '{domain}'.\n")
                self.result_text.insert(tk.END, "-" * 60 + "\n\n")
                return  # Esce senza procedere con l'analisi

            # Se il dominio esiste, procediamo con l'analisi DKIM
            result = DKIMRecordAnalyzer.extract_dkim_records(domain, selectors)

            with open(self.results_filename, 'a', encoding='utf-8') as results_file:
                results_file.write("=" * 60 + "\n")
                results_file.write(f"✅ Domain: {domain} (Exists)\n")
                results_file.write("=" * 60 + "\n")
                results_file.write(f"Status: {result['status']}\n\n")

                self.result_text.insert(tk.END, "=" * 60 + "\n")
                self.result_text.insert(tk.END, f"✅ Domain: {domain} (Exists)\n")
                self.result_text.insert(tk.END, "=" * 60 + "\n")
                self.result_text.insert(tk.END, f"Status: {result['status']}\n\n")

                if result['status'] == 'No records found':
                    self.result_text.insert(tk.END, f"⚠️ No DKIM records found for '{domain}'.\n")
                    self.result_text.insert(tk.END, "-" * 60 + "\n\n")
                    return  # Evita di stampare dati inesistenti

                for i, record in enumerate(result['records'], 1):
                    results_file.write(f"DKIM Record {i}:\n")
                    self.result_text.insert(tk.END, f"DKIM Record {i}:\n")

                    # Status di validazione
                    status_text = "✓ Valid" if record.get('validation_results', {}).get('is_valid', False) else "✗ Invalid"
                    
                    results_file.write(f"    Validation Status: {status_text}\n")
                    self.result_text.insert(tk.END, f"    Validation Status: {status_text}\n")

                    # Selettore e dettagli chiave
                    for field in ['selector', 'v', 'k']:
                        value = record.get(field, 'N/A')
                        results_file.write(f"    {field}: {value}\n")
                        self.result_text.insert(tk.END, f"    {field}: {value}\n")

                    # Chiave pubblica
                    if 'p' in record:
                        public_key = record['p']
                        results_file.write(f"    Public Key: {public_key}\n")
                        self.result_text.insert(tk.END, f"    Public Key: {public_key}\n")
                    else:
                        results_file.write("    Public Key: Not Found\n")
                        self.result_text.insert(tk.END, "    Public Key: Not Found\n")

                    results_file.write("\n" + "-" * 60 + "\n\n")
                    self.result_text.insert(tk.END, "\n" + "-" * 60 + "\n\n")

                self.result_text.see(tk.END)

        except Exception as e:
            error_message = f"❌ ERROR: An error occurred while analyzing '{domain}': {e}"
            self.result_text.insert(tk.END, error_message + "\n")
            self.result_text.see(tk.END)
            self.logger.error(error_message)

    def _perform_multi_domain_analysis(self, domains, selectors=None):
        """
        Perform DKIM analysis for multiple domains and display results in the GUI.
        """
        try:
            with open(self.results_filename, 'w', encoding='utf-8') as results_file:
                for domain in domains:
                    # Verifica esistenza dominio
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = ["8.8.8.8"]
                    domain_exists = False
                    
                    try:
                        resolver.resolve(domain, 'A')
                        domain_exists = True
                    except dns.resolver.NXDOMAIN:
                        error_msg = f"❌ ERROR: Domain '{domain}' does not exist"
                        self.result_text.insert(tk.END, error_msg + "\n")
                        results_file.write(error_msg + "\n")
                        continue
                    except (dns.resolver.NoAnswer, dns.exception.Timeout):
                        warning_msg = f"⚠️ WARNING: Unable to verify existence of '{domain}'"
                        self.result_text.insert(tk.END, warning_msg + "\n")
                        results_file.write(warning_msg + "\n")
                        continue
                    except Exception as e:
                        error_msg = f"❌ ERROR: DNS resolution failed for '{domain}': {str(e)}"
                        self.result_text.insert(tk.END, error_msg + "\n")
                        results_file.write(error_msg + "\n")
                        continue

                    # Procedi con l'analisi DKIM solo se il dominio esiste
                    result = DKIMRecordAnalyzer.extract_dkim_records(domain, selectors)

                    # Write to file
                    results_file.write("=" * 60 + "\n")
                    results_file.write(f"Domain: {domain}\n")
                    results_file.write("=" * 60 + "\n")
                    results_file.write(f"Status: {result['status']}\n\n")

                    # Show in GUI
                    self.result_text.insert(tk.END, "=" * 60 + "\n")
                    self.result_text.insert(tk.END, f"Domain: {domain}\n")
                    self.result_text.insert(tk.END, "=" * 60 + "\n")
                    self.result_text.insert(tk.END, f"Status: {result['status']}\n\n")

                    if result['status'] == 'No records found':
                        #self.result_text.insert(tk.END, f"⚠️ No DKIM records found for '{domain}'.\n")
                        self.result_text.insert(tk.END, "-" * 60 + "\n\n")
                        continue

                    for i, record in enumerate(result['records'], 1):
                        # Get validation results
                        validation_results = record.get('validation_results', {})
                        status_text = "✓ Valid" if validation_results.get('is_valid', False) else "✗ Invalid"
                        security_level = validation_results.get('security_level', 'UNKNOWN')

                        # Write to file
                        results_file.write(f"DKIM Record {i}:\n")
                        results_file.write(f"    Validation Status: {status_text}\n")
                        results_file.write(f"    Selector: {record.get('selector', 'N/A')}\n")
                        results_file.write(f"    Version: {record.get('v', 'N/A')}\n")
                        results_file.write(f"    Key Type: {record.get('k', 'N/A')}\n")

                        # Show in GUI
                        self.result_text.insert(tk.END, f"DKIM Record {i}:\n")
                        self.result_text.insert(tk.END, f"    Validation Status: {status_text}\n")
                        self.result_text.insert(tk.END, f"    Selector: {record.get('selector', 'N/A')}\n")
                        self.result_text.insert(tk.END, f"    Version: {record.get('v', 'N/A')}\n")
                        self.result_text.insert(tk.END, f"    Key Type: {record.get('k', 'N/A')}\n")

                        # Display errors if any
                        if validation_results.get('errors'):
                            results_file.write("    Errors:\n")
                            self.result_text.insert(tk.END, "    Errors:\n")
                            for error in validation_results['errors']:
                                results_file.write(f"      - {error}\n")
                                self.result_text.insert(tk.END, f"      - {error}\n")

                        if 'p' in record:
                            public_key = record['p']
                            key_length = len(public_key)
                            results_file.write(f"    Public Key: {public_key}\n")
                            results_file.write(f"    Public Key Length: {key_length} characters\n")
                            self.result_text.insert(tk.END, f"    Public Key: {public_key}\n")
                            self.result_text.insert(tk.END, f"    Public Key Length: {key_length} characters\n")
                        else:
                            results_file.write("    Public Key: Not Found\n")
                            self.result_text.insert(tk.END, "    Public Key: Not Found\n")

                        
                        results_file.write("\n" + "-" * 60 + "\n\n")
                        self.result_text.insert(tk.END, "\n" + "-" * 60 + "\n\n")

                    # Scroll to end
                    self.result_text.see(tk.END)

        except Exception as e:
            error_message = f"Error during multi-domain analysis: {e}"
            self.result_text.insert(tk.END, error_message + "\n")
            self.result_text.see(tk.END)


    def _update_progress_label(self, text):
        """
        Update the progress label
        """
        self.progress_label.config(text=text)

    def _append_results(self, message):
        """
        Append results to the output text area with improved formatting.
        """
        self.result_text.insert(tk.END, "=" * 60 + "\n")
        self.result_text.insert(tk.END, f"{message}\n")
        self.result_text.insert(tk.END, "=" * 60 + "\n\n")

        for result in message.split("\n\n"):
            if not result.strip():
                continue
            self.result_text.insert(tk.END, result + "\n\n")

        self.result_text.see(tk.END)


    def _append_text(self, text):
        """
        Append text to the results area
        """
        self.result_text.insert(tk.END, text)
        self.result_text.see(tk.END)

    def _show_error(self, message):
        """
        Display error messages
        """
        messagebox.showerror("Error", message)

    def _clear_results(self):
        """
        Clear results and input
        """
        self.result_text.delete(1.0, tk.END)
        self.domain_text.delete(1.0, tk.END)
        self.progress_label.config(text="")
        if hasattr(self, 'custom_selectors'):
            del self.custom_selectors

    def _get_custom_selectors(self):
            """
            Allow user to input custom DKIM selectors
            """
            selectors_input = simpledialog.askstring(
                "Custom Selectors", 
                "Enter custom DKIM selectors (comma-separated):"
            )
            
            if selectors_input:
                self.custom_selectors = [s.strip() for s in selectors_input.split(',')]
                messagebox.showinfo(
                    "Custom Selectors", 
                    f"Added {len(self.custom_selectors)} custom selectors"
                )

class EmailDKIMVerifier:
    @staticmethod
    def extract_dkim_header(email_content):
        """
        Extract DKIM-Signature headers from the email content.
        """
        headers = []
        try:
            message = BytesParser(policy=policy.default).parsebytes(email_content)
            headers = message.get_all('DKIM-Signature', [])
        except Exception as e:
            print(f"Error parsing email: {e}")
        return headers

    @staticmethod
    def parse_dkim_signature(signature):
        """
        Parse a DKIM-Signature header into a dictionary of fields.
        """
        fields = {}
        try:
            for part in signature.split(';'):
                part = part.strip()
                if '=' in part:
                    key, value = part.split('=', 1)
                    fields[key.strip()] = value.strip()
        except Exception as e:
            print(f"Error parsing DKIM signature: {e}")
        return fields

    @staticmethod
    def validate_dkim_signature(domain, selector):
        """
        Retrieve and validate the DKIM public key from DNS.
        """
        try:
            query = f"{selector}._domainkey.{domain}"
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            print(f"Querying DKIM record: {query}")  # Debug output
            txt_records = resolver.resolve(query, 'TXT')
            for txt in txt_records:
                # Convert bytes to string
                record = ''.join([entry.decode('utf-8') if isinstance(entry, bytes) else entry for entry in txt.strings])
                if 'v=DKIM1' in record:
                    print(f"Found DKIM record: {record}")  # Debug output
                    return record
        except dns.resolver.NoAnswer:
            print(f"No DKIM record found for {query}.")
        except Exception as e:
            print(f"Error validating DKIM record: {e}")
        return None


    @staticmethod
    def verify_email_dkim(email_content):
        """
        Verify DKIM signatures in an email.
        """
        results = []
        headers = EmailDKIMVerifier.extract_dkim_header(email_content)

        for header in headers:
            fields = EmailDKIMVerifier.parse_dkim_signature(header)
            domain = fields.get('d')
            selector = fields.get('s')

            if not domain or not selector:
                results.append({
                    'status': 'Error',
                    'message': 'Missing domain (d) or selector (s) in DKIM signature.'
                })
                continue

            dkim_record = EmailDKIMVerifier.validate_dkim_signature(domain, selector)

            if not dkim_record:
                results.append({
                    'status': 'Failed',
                    'message': f"No valid DKIM record found for domain {domain} and selector {selector}."
                })
            else:
                results.append({
                    'status': 'Success',
                    'message': f"Valid DKIM record found for domain {domain} and selector {selector}.",
                    'record': dkim_record
                })

        return results

def setup_logging_and_results(is_cli=False):
    """
    Configure logging and results file.
    If is_cli is True, the filenames are adjusted for CLI use.
    """
    log_dir = "logs"
    results_dir = "results"
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(results_dir, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    prefix = "cli" if is_cli else "gui"
    log_filename = os.path.join(log_dir, f"{prefix}_log_{timestamp}.log")
    results_filename = os.path.join(results_dir, f"{prefix}_results_{timestamp}.txt")

    logging.basicConfig(
        filename=log_filename,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s: %(message)s'
    )
    logger = logging.getLogger(__name__)

    return logger, results_filename

def run_cli():
    logger, results_filename = setup_logging_and_results(is_cli=True)
    while True:
        print("\nOptions:")
        print("1. Analyze a domain for DKIM records")
        print("2. Analyze an email for DKIM signatures")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            domain = input("Enter the domain to analyze: ")
            if DKIMRecordAnalyzer.validate_domain(domain):
                print(f"Analyzing DKIM records for domain: {domain}")
                print("Performing DNS queries, please wait...")
                result = DKIMRecordAnalyzer.extract_dkim_records(domain)
                
                # Salvataggio dei risultati nel file results
                with open(results_filename, 'a', encoding='utf-8') as results_file:
                    results_file.write("=" * 60 + "\n")
                    results_file.write(f"Domain: {domain}\n")
                    results_file.write(f"Status: {result['status']}\n")
                    for record in result['records']:
                        results_file.write(f"Selector: {record.get('selector', 'N/A')}\n")
                        results_file.write(f"Record: {record.get('raw_record', 'N/A')}\n")
                        results_file.write("-" * 60 + "\n")
                
                logger.info(f"Analysis completed for domain: {domain}")
                
                # Stampa dei risultati nella CLI
                print("=" * 60)
                print(f"Domain: {domain}")
                print(f"Status: {result['status']}")
                for record in result['records']:
                    print("-" * 60)
                    print(f"Selector: {record.get('selector', 'N/A')}")
                    print(f"Record: {record.get('raw_record', 'N/A')}")
                print("=" * 60)
            else:
                print(f"Invalid domain: {domain}")
        elif choice == '2':
            email_path = input("Enter the path to the email file (.eml): ").strip()

            if not os.path.isfile(email_path):
                print(f"Error: File not found at '{email_path}'. Please check the path and try again.")
            else:
                try:
                    with open(email_path, 'rb') as f:
                        email_content = f.read()
                    print("Analyzing email for DKIM signatures...")
                    results = EmailDKIMVerifier.verify_email_dkim(email_content)

                    with open(results_filename, 'a', encoding='utf-8') as results_file:
                        results_file.write("=" * 60 + "\n")
                        results_file.write(f"Email File: {email_path}\n")
                        for result in results:
                            results_file.write(f"Status: {result['status']}\n")
                            results_file.write(f"Message: {result['message']}\n")
                            if 'record' in result:
                                results_file.write(f"Record: {result['record']}\n")
                            results_file.write("-" * 60 + "\n")

                    logger.info(f"Analysis completed for email: {email_path}")

                    print("=" * 60)
                    for result in results:
                        print(f"Status: {result['status']}")
                        print(f"Message: {result['message']}")
                        if 'record' in result:
                            print(f"Record: {result['record']}")
                        print("-" * 60)
                    print("=" * 60)
                except Exception as e:
                    print(f"Error reading the file: {e}")

        elif choice == '3':
            print("Exiting the CLI. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


def main():
    print("Welcome to the DKIM Analyzer!")
    print("1. CLI (Command Line Interface)")
    print("2. GUI (Graphical User Interface)")
    choice = input("Choose an interface (1 for CLI, 2 for GUI): ")

    if choice == '1':
        run_cli()
    elif choice == '2':
        root = tk.Tk()
        app = DKIMExtractorGUI(root)
        root.mainloop()
    else:
        print("Invalid choice. Please select 1 for CLI or 2 for GUI.")

if __name__ == "__main__":
    main()

