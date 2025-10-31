"""
Centralized logging utility for MASTR Host
Provides color-coded console output with consistent formatting
"""

# ANSI Color Codes
class Colors:
    """ANSI escape codes for terminal colors"""
    RESET = '\033[0m'
    ORANGE = '\033[38;5;214m'
    GREEN = '\033[38;5;46m'
    RED = '\033[38;5;196m'
    YELLOW = '\033[38;5;208m'
    CYAN = '\033[38;5;51m'
    MAGENTA = '\033[38;5;201m'


class Logger:
    """
    Centralized logging with color support.
    Provides consistent formatting for all output types.
    """
    
    # Class variable for verbose mode
    verbose: bool = False
    
    @staticmethod
    def success(message: str) -> None:
        """Print success message with green checkmark"""
        print(f"{Colors.GREEN}✓{Colors.RESET} {message}")
    
    @staticmethod
    def error(message: str) -> None:
        """Print error message with red X"""
        print(f"{Colors.RED}✗{Colors.RESET} {message}")
    
    @staticmethod
    def info(message: str) -> None:
        """Print info message with cyan color"""
        print(f"{Colors.CYAN}[INFO]{Colors.RESET} {message}")
    
    @staticmethod
    def warning(message: str) -> None:
        """Print warning message with yellow color"""
        print(f"{Colors.YELLOW}[WARNING]{Colors.RESET} {message}")
    
    @staticmethod
    def debug(tag: str, message: str) -> None:
        """Print debug message with orange color"""
        print(f"{Colors.ORANGE}[{tag}]{Colors.RESET} {message}")
    
    @staticmethod
    def section(title: str) -> None:
        """Print section header with cyan color"""
        print(f"\n{Colors.CYAN}=== {title} ==={Colors.RESET}")
    
    @staticmethod
    def header(text: str) -> None:
        """Print major header with separator"""
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}{text}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    
    @staticmethod
    def success_header(text: str) -> None:
        """Print success header with green separator"""
        print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}")
        print(f"{Colors.GREEN}{text}{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
    
    @staticmethod
    def step(step_num: int, description: str) -> None:
        """Print numbered step"""
        print(f"\n{step_num}. {description}")
    
    @staticmethod
    def substep(message: str) -> None:
        """Print indented substep with info"""
        print(f"   {message}")
    
    @staticmethod
    def tagged(tag: str, color: str, message: str) -> None:
        """Print message with custom colored tag"""
        print(f"{color}[{tag}]{Colors.RESET} {message}")