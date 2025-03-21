from core import config
import sys
import argparse,os
from core.config import Setup

def setup():
    # Call the setup function from core/config
    setup_instance = Setup()
    setup_instance.setup_prompt()

def run_service():
    # Code to run the Heimdell service
    print("Running Heimdell service...")

def healthcheck():
    # Code to perform a health check
    print("Performing Heimdell health check...")

def manage_modules():
    # Code to manage Heimdell modules
    print("Managing Heimdell modules...")

    # List available modules by files in modules folder and status if installed if listed in .config.ini under [INSTALLED_MODULES]
    modules_folder = "modules"
    module_files = [f for f in os.listdir(modules_folder) if os.path.isfile(os.path.join(modules_folder, f))]

    print("Available modules:")
    for module_file in module_files:
        module_name = os.path.splitext(module_file)[0]  # Remove the file extension
        
        # Check if the module is installed
        module_config = config.Setup().get_from_config('INSTALLED', module_name.upper())
        installed = "Installed" if module_config else "Not Installed"

        print(f"- {module_name} ({installed})")

    # Prompt for module management actions
    while True:
        print("\nModule Management Actions:")
        print("1. Install/Update Module")
        print("2. Uninstall Module")
        print("0. Back to main menu")

        choice = input("Heimdell(Select an option) #> ").strip()

        if choice == "0":
            break
        elif choice == "1":
            module_to_install = input("Heimdell(Enter module name to install/update) #> ").strip()
            # Implement module installation logic here
            setup_instance = Setup()
            setup_instance.add_to_config('INSTALLED', module_to_install.upper(), 'true')
            print(f"Installing/Updating module: {module_to_install}")
        elif choice == "2":
            module_to_uninstall = input("Heimdell(Enter module name to uninstall) #> ").strip()
            # Implement module uninstallation logic here
            print(f"Uninstalling module: {module_to_uninstall}")
        else:
            print("Invalid option. Please try again.")

# Import the SnortModule class
from modules.snort import SnortModule

def run_module(module_name):
    """Run a specific Heimdell module"""
    if module_name.lower() == "snort":
        # Load Snort configuration from .config.ini
        snort_config = config.get_from_config('INSTALLED', 'SNORT')
        snort_module = SnortModule(snort_config)

        # Run the Snort module
        snort_module.run()
    else:
        print(f"Module '{module_name}' not found or not implemented yet.")

def main():
    parser = argparse.ArgumentParser(description="Heimdell Agent")
    parser.add_argument("command", choices=["setup", "modules", "healthcheck", "runservice", "runmodule"])
    parser.add_argument("module", nargs="?", default=None)
    args = parser.parse_args()

    if args.command == "setup":
        setup()
    elif args.command == "modules":
        manage_modules()
    elif args.command == "healthcheck":
        healthcheck()
    elif args.command == "runservice":
        run_service()
    elif args.command == "runmodule":
        if args.module:
            run_module(args.module)
        else:
            print("Please specify a module name to run.")
    else:
        print("Invalid command")

if __name__ == "__main__":
    main()
