from core import config
import sys
import argparse, os
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
    setup_instance = Setup()

    # List available modules by files in modules folder and status if installed if listed in .config.ini under [INSTALLED_MODULES]
    modules_folder = "modules"
    
    # Check if the modules folder exists
    if not os.path.exists(modules_folder) or not os.path.isdir(modules_folder):
        print(f"Error: Modules folder '{modules_folder}' not found or is not a directory")
        return
    
    available_modules = []
    module_files = [f for f in os.listdir(modules_folder) if os.path.isfile(os.path.join(modules_folder, f))]
    
    for module_file in module_files:
        # Only consider python files
        if module_file.endswith('.py'):
            module_name = os.path.splitext(module_file)[0]  # Remove the file extension
            available_modules.append(module_name)
    
    print("Available modules:")
    if not available_modules:
        print("  No modules found in the modules directory.")
    else:
        for module_name in available_modules:
            # Check if the module is installed
            module_config = setup_instance.get_from_config('INSTALLED', module_name.upper())
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
            
            # Validate module exists
            if module_to_install.lower() not in [m.lower() for m in available_modules]:
                print(f"Error: Module '{module_to_install}' not found in the modules directory")
                continue
            
            # Convert to uppercase for configuration consistency
            module_name_upper = module_to_install.upper()
            
            # Check if already installed
            if setup_instance.get_from_config('INSTALLED', module_name_upper):
                print(f"Module '{module_to_install}' is already installed. Updating configuration...")
            else:
                print(f"Installing module: {module_to_install}")
            
            # Add to configuration
            setup_instance.add_to_config('INSTALLED', module_name_upper, 'true')
            print(f"Module '{module_to_install}' installation/update complete")
            
        elif choice == "2":
            module_to_uninstall = input("Heimdell(Enter module name to uninstall) #> ").strip()
            
            # Convert to uppercase for configuration consistency
            module_name_upper = module_to_uninstall.upper()
            
            # Check if installed before uninstalling
            if not setup_instance.get_from_config('INSTALLED', module_name_upper):
                print(f"Module '{module_to_uninstall}' is not installed")
                continue
            
            # Remove from configuration
            if setup_instance.remove_from_config('INSTALLED', module_name_upper):
                print(f"Module '{module_to_uninstall}' uninstalled successfully")
            else:
                print(f"Error uninstalling module '{module_to_uninstall}'")
        else:
            print("Invalid option. Please try again.")

# Import the SnortModule class
# Note: This should be moved to a dynamic import in the run_module function
# to avoid issues when the module is not installed
# from modules.snort import SnortModule

def run_module(module_name):
    """
    Run a specific Heimdell module
    
    Args:
        module_name: Name of the module to run
    """
    setup_instance = Setup()
    
    # Check if module is installed
    module_config = setup_instance.get_from_config('INSTALLED', module_name.upper())
    if not module_config:
        print(f"Module '{module_name}' is not installed. Would you like to install it now?")
        choice = input("Heimdell(Install module? [y/n]) #> ").strip().lower()
        
        if choice != 'y':
            print("Module installation cancelled.")
            return
        
        # Check if module exists in modules folder
        module_path = os.path.join("modules", f"{module_name.lower()}.py")
        if not os.path.exists(module_path):
            print(f"Error: Module file '{module_path}' not found")
            return
        
        # Install the module
        print(f"Installing module: {module_name}")
        setup_instance.add_to_config('INSTALLED', module_name.upper(), 'true')
        print(f"Module '{module_name}' has been installed.")
    
    print(f"Running module: {module_name}")
    
    # Dynamically import and run the module
    try:
        # Convert module name to proper import format
        module_import = f"modules.{module_name.lower()}"
        
        # Import the module
        module = __import__(module_import, fromlist=[f'{module_name.capitalize()}Module'])
        
        # Get the module class (assuming naming convention ModuleNameModule)
        module_class_name = f'{module_name.capitalize()}Module'
        ModuleClass = getattr(module, module_class_name)
        
        # Get configuration for this module from the INSTALLED section
        # and any specific module section if it exists
        module_config = {}
        
        # First check if there's a specific section for this module
        module_section = module_name.upper()
        if setup_instance.config.has_section(module_section):
            for key, value in setup_instance.config[module_section].items():
                module_config[key] = value
        
        # Initialize and run the module
        module_instance = ModuleClass(module_config)
        
        # Check if the run method exists
        if not hasattr(module_instance, 'run'):
            print(f"Error: Module '{module_name}' does not have a 'run' method.")
            return
        
        # Run the module
        module_instance.run()
        
    except ImportError as e:
        print(f"Error importing module '{module_name}': {e}")
    except AttributeError as e:
        print(f"Error: Module class not found in '{module_name}': {e}")
    except Exception as e:
        print(f"Error running module '{module_name}': {e}")
        import traceback
        traceback.print_exc()

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