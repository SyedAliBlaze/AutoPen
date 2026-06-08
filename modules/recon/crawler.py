# AutoPen Web Crawler Module
# Automatically discovers pages, forms, and parameters
# No hardcoded paths - works on any web application
# Feeds discovered targets to SQLi and XSS scanners

import requests
from urllib.parse import urlparse, urljoin, parse_qs
from html.parser import HTMLParser
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()


class LinkParser(HTMLParser):
    """
    Parses HTML and extracts:
    - All href links
    - All forms with input fields
    We write our own parser - no external library
    """
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links = set()
        self.forms = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        # Extract links from anchor tags
        if tag == 'a' and 'href' in attrs:
            href = attrs['href']
            if href and not href.startswith('#') and not href.startswith('javascript'):
                full_url = urljoin(self.base_url, href)
                self.links.add(full_url)

        # Extract form details
        if tag == 'form':
            self._current_form = {
                'action': urljoin(self.base_url, attrs.get('action', '')),
                'method': attrs.get('method', 'get').upper(),
                'inputs': []
            }

        # Extract input fields
        if tag == 'input' and self._current_form is not None:
            input_type = attrs.get('type', 'text').lower()
            input_name = attrs.get('name', '')
            input_value = attrs.get('value', 'test')

            if input_name and input_type not in ['submit', 'button', 'image', 'reset']:
                self._current_form['inputs'].append({
                    'name': input_name,
                    'type': input_type,
                    'value': input_value
                })

        # Extract select fields
        if tag == 'select' and self._current_form is not None:
            select_name = attrs.get('name', '')
            if select_name:
                self._current_form['inputs'].append({
                    'name': select_name,
                    'type': 'select',
                    'value': '1'
                })

        # Extract textarea fields
        # Critical: DVWA xss_s uses <textarea name="mtxMessage">
        # which is invisible to input-only parsers
        if tag == 'textarea' and self._current_form is not None:
            textarea_name = attrs.get('name', '')
            if textarea_name:
                self._current_form['inputs'].append({
                    'name': textarea_name,
                    'type': 'textarea',
                    'value': 'test'
                })

    def handle_endtag(self, tag):
        if tag == 'form' and self._current_form is not None:
            if self._current_form['inputs']:
                self.forms.append(self._current_form)
            self._current_form = None


class WebCrawler:
    def __init__(self, config: dict, logger, session: requests.Session):
        self.base_url = config['target']['dvwa_url']
        self.target_ip = config['target']['host']
        self.timeout = config['scan']['timeout']
        self.logger = logger
        self.session = session
        self.max_pages = 100
        self.visited_urls = set()
        self.discovered_urls = []
        self.discovered_forms = []
        self.discovered_params = []

    def run(self) -> dict:
        """
        Main crawl function.
        Returns all discovered targets for scanners.
        """
        console.print(Panel(
            "[bold cyan]WEB CRAWLER[/bold cyan]\n"
            f"Starting point: [bold white]{self.base_url}[/bold white]\n"
            "Discovering pages, forms, and parameters...",
            style="cyan"
        ))

        # Start crawling from base URL
        self._crawl(self.base_url)

        # Extract GET parameters from discovered URLs
        self._extract_get_params()

        # Display results
        self._display_results()

        return {
            'urls': self.discovered_urls,
            'forms': self.discovered_forms,
            'get_params': self.discovered_params
        }

    def _crawl(self, start_url: str):
        """
        Breadth-first crawl starting from start_url.
        Stays within same host - never leaves target.
        """
        queue = [start_url]

        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]Crawling: {task.description}[/cyan]"),
            transient=True
        ) as progress:
            task = progress.add_task("starting...", total=None)

            while queue and len(self.visited_urls) < self.max_pages:
                url = queue.pop(0)

                # Skip if already visited
                if url in self.visited_urls:
                    continue

                # Stay on same host only
                if not self._is_same_host(url):
                    continue

                # Skip non-HTTP links
                if not url.startswith('http'):
                    continue

                try:
                    response = self.session.get(
                        url,
                        timeout=self.timeout,
                        allow_redirects=True
                    )

                    self.visited_urls.add(url)
                    self.discovered_urls.append(url)
                    self.logger.log_request('GET', url, response.status_code)

                    progress.update(task, description=url[-50:])

                    # Only parse HTML responses
                    content_type = response.headers.get('content-type', '')
                    if 'html' not in content_type:
                        continue

                    # Parse page for links and forms
                    parser = LinkParser(url)
                    parser.feed(response.text)

                    # Save discovered forms
                    for form in parser.forms:
                        form['found_on'] = url
                        self.discovered_forms.append(form)

                    # Add new links to queue
                    for link in parser.links:
                        if link not in self.visited_urls:
                            queue.append(link)

                except requests.exceptions.Timeout:
                    pass
                except requests.exceptions.ConnectionError:
                    pass
                except Exception as e:
                    self.logger.log_error('crawler', str(e))

    def _is_same_host(self, url: str) -> bool:
        """
        Ensure crawler never leaves target host.
        Critical safety check.
        """
        try:
            parsed = urlparse(url)
            # Must have a valid scheme
            if parsed.scheme not in ['http', 'https']:
                return False
            # Must have a hostname
            if not parsed.hostname:
                return False
            # Must match target IP exactly
            target_parsed = urlparse(self.base_url)
            return parsed.hostname == target_parsed.hostname
        except Exception:
            return False

    def _extract_get_params(self):
        """
        Extract URLs with GET parameters.
        Deduplicate forms and parameters.
        """
        # Deduplicate GET parameters by url+param key
        seen_params = set()
        unique_params = []
        for url in self.discovered_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params:
                for param_name in params:
                    key = f"{parsed.hostname}{parsed.path}_{param_name}"
                    if key not in seen_params:
                        seen_params.add(key)
                        unique_params.append({
                            'url': url,
                            'param': param_name,
                            'original_value': params[param_name][0]
                        })
        self.discovered_params = unique_params

        # Deduplicate forms by action+method key
        seen_forms = set()
        unique_forms = []
        for form in self.discovered_forms:
            action = form.get('action', '')
            method = form.get('method', 'GET')
            parsed = urlparse(action)
            key = f"{parsed.hostname}{parsed.path}_{method}"
            if key not in seen_forms:
                seen_forms.add(key)
                unique_forms.append(form)
        self.discovered_forms = unique_forms

    def _display_results(self):
        """Display crawler results"""

        # Pages discovered
        console.print(f"\n[bold cyan]Pages Discovered: {len(self.discovered_urls)}[/bold cyan]")

        # GET parameters table
        if self.discovered_params:
            param_table = Table(
                title="Discovered GET Parameters",
                box=box.ROUNDED,
                style="yellow"
            )
            param_table.add_column("URL", style="white")
            param_table.add_column("Parameter", style="bold yellow")
            param_table.add_column("Value", style="cyan")

            for p in self.discovered_params:
                param_table.add_row(
                    p['url'][-60:],
                    p['param'],
                    p['original_value']
                )
            console.print(param_table)

        # Forms table
        if self.discovered_forms:
            form_table = Table(
                title="Discovered Forms",
                box=box.ROUNDED,
                style="green"
            )
            form_table.add_column("Action URL", style="white")
            form_table.add_column("Method", style="bold")
            form_table.add_column("Input Fields", style="cyan")

            for form in self.discovered_forms:
                inputs = ", ".join([i['name'] for i in form['inputs']])
                form_table.add_row(
                    form['action'][-60:],
                    form['method'],
                    inputs
                )
            console.print(form_table)

        console.print(
            f"[green]GET Parameters found: {len(self.discovered_params)}[/green] | "
            f"[green]Forms found: {len(self.discovered_forms)}[/green]"
        )
