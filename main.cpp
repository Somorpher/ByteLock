#include "FSController.hpp"            // include this for file system operations
#include "gcm.hpp"          // include this for encryption/decryption

#if defined(__GNUC__) || defined(__GNUG__) || defined(__clang__)
// basic compiler specific optimization...
#define __attribute_0x0__ __attribute__((cold, optimize(3)))
#define __attribute_0x1__ __attribute__((const, optimize(3)))
#define __attribute_0x2__ __attribute__((hot, pure, optimize(3)))
#define __attribute_0x3__ __attribute__((cold, optimize(3)))
#define __attribute_0x4__ __attribute__((hot, optimize(3)))
#define __attribute_0x5__ __attribute__((hot, optimize(3)))
#define __attribute_0x6__ __attribute__((cold, optimize(3)))
#define __attribute_0x7__ __attribute__((hot, access(read_only, 1), access(read_only, 2), optimize(3)))
#define __attribute_0x8__ __attribute__((hot, access(read_only, 1), access(read_only, 2), optimize(3)))

#else
#define __attribute_0x0__ [[]]
#define __attribute_0x1__ [[nothrow]]
#define __attribute_0x2__ [[nothrow]]
#define __attribute_0x3__ [[nothrow]]
#define __attribute_0x4__ [[nothrow]]
#define __attribute_0x5__ [[]]
#define __attribute_0x6__ [[nothrow]]
#define __attribute_0x7__ [[nothrow]]
#define __attribute_0x8__ [[nothrow]]
#endif

#define MAX_SUBSET_SIZE (std::uint16_t)200u
#define FILE_MAX_BLOCK_SIZE 1024u * 7
#define DESCRIPTOR_SIZE_THRESHOLD 1
#define SECRET_BLOCK_SIZE_THRESHOLD 7
#define SECRET_BLOCK_SIZE_MAX 1024*4

#if defined(__linux__) || defined(__APPLE__)
#define FG_COLOR_RESET   "\033[0m"  // Reset to default color
#define FG_COLOR_BLACK   "\033[30m"  // Black
#define FG_COLOR_RED     "\033[31m"  // Red
#define FG_COLOR_GREEN   "\033[32m"  // Green
#define FG_COLOR_YELLOW  "\033[33m"  // Yellow
#define FG_COLOR_BLUE    "\033[34m"  // Blue
#define FG_COLOR_MAGENTA "\033[35m"  // Magenta
#define FG_COLOR_CYAN    "\033[36m"  // Cyan
#define FG_COLOR_WHITE   "\033[37m"  // White
#else // fallback values
#define FG_COLOR_RESET   ""  // Reset to default color
#define FG_COLOR_BLACK   ""  // Black
#define FG_COLOR_RED     ""  // Red
#define FG_COLOR_GREEN   ""  // Green
#define FG_COLOR_YELLOW  ""  // Yellow
#define FG_COLOR_BLUE    ""  // Blue
#define FG_COLOR_MAGENTA ""  // Magenta
#define FG_COLOR_CYAN    ""  // Cyan
#define FG_COLOR_WHITE   ""  // White
#endif


using namespace ByteCryptModule;    // encryption/decryption module
using namespace FSControllerModule; // filesystem manager module

__attribute_0x0__ static void GetCLI(int, char **);
__attribute_0x1__ inline static const string_t subset_extract(const string_view_t) noexcept;
__attribute_0x2__ inline static bool do_execute(const string_view_t message) noexcept;
__attribute_0x3__ static void print_man() noexcept;
__attribute_0x3__ static void print_man_interface(void) noexcept;
__attribute_0x4__ inline static void prompt_interface(void) noexcept;
__attribute_0x5__ inline static void execute_command(void);
__attribute_0x6__ static void set_atomic_execution(const bool mode) noexcept;
__attribute_0x7__ static void encrypt_directory(FSController<string_t>* fsi,ByteCrypt* bci);
__attribute_0x8__ static void encrypt_file(FSController<string_t>* fsi, ByteCrypt* bci);
static inline void show_target_content();

enum class OPERATION_MODE : std::uint16_t
{
    ENCRYPTION = 0,
    DECRYPTION,
    NONE
};

typedef struct alignas(void *)
{
    string_t secret{};
    string_t target_path{};
    string_t backup_path{};
    OPERATION_MODE mode{OPERATION_MODE::NONE};
    bool backup{false};
    bool recursive{false};
    bool verbose{false};
    bool direct_execution{false}; // if this is set to false, will start encryption/decryption right aways, if false, will stop and ask before execution on most critical parts
    bool help_screen{false};
    bool interface_mode{false};
    bool atomic_execution{false};
} flags;

static flags cli_flags;

int main(int argc, char **argv)
{
    GetCLI(argc, argv); // collect command line arguments

    if(cli_flags.direct_execution && !cli_flags.interface_mode)
    {
        if (cli_flags.mode == OPERATION_MODE::NONE)
            throw std::invalid_argument("either use encryption `--encrypt` or decryption `--decrypt`");
        if (cli_flags.secret.empty())
            throw std::invalid_argument("No secret key supplied `--secret=...`");
        if (cli_flags.target_path.empty())
            throw std::invalid_argument("provide fucking target `--target=...`");
        if (cli_flags.mode != OPERATION_MODE::ENCRYPTION && cli_flags.mode != OPERATION_MODE::DECRYPTION)
            throw std::invalid_argument("either you must encrypt `--encrypt` or decrypt `--decrypt`");
        execute_command();
    }
        if (cli_flags.help_screen)
        {
            print_man();
            return EXIT_SUCCESS;
        }

        prompt_interface();
    return EXIT_SUCCESS;
};

static void GetCLI(int argc, char **argv)
{
    if (argc > 1)
    {
        std::uint16_t arg_index_count(1);
        do
        {
            const string_t current(argv[arg_index_count]);
            if (current.compare("--backup") == 0)
                cli_flags.backup = true;
            else if (current.length() >= 12 && current.find("=") != string_t::npos && current.substr(0, 13).compare("--backup-path") == 0)
                cli_flags.backup_path = subset_extract(argv[arg_index_count]);
            else if (current.compare("--recursive") == 0)
                cli_flags.recursive = true;
            else if (current.compare("--verbose") == 0)
                cli_flags.verbose = true;
            else if (current.length() > 8 && current.find("=") != string_t::npos && current.substr(0, 8).compare("--secret") == 0)
                cli_flags.secret = subset_extract(argv[arg_index_count]);
            else if (current.length() > 8 && current.find("=") != string_t::npos && current.substr(0, 8).compare("--target") == 0)
                cli_flags.target_path = subset_extract(argv[arg_index_count]);
            else if (current.length() > 13 && current.find("=") != string_t::npos && current.substr(0, 13).compare("--backup-path") == 0)
                cli_flags.backup_path = subset_extract(argv[arg_index_count]);
            else if (current.compare("--encrypt") == 0)
                cli_flags.mode = OPERATION_MODE::ENCRYPTION;
            else if (current.compare("--decrypt") == 0)
                cli_flags.mode = OPERATION_MODE::DECRYPTION;
            else if (current.compare("--direct") == 0)
                cli_flags.direct_execution = true;
            else if (current.compare("--interface") == 0)
                cli_flags.interface_mode = true;
            else if (current.compare("--help") == 0 || current.compare("-help") == 0 || current.compare("help") == 0 || current.compare("-h") == 0)
            {
                print_man_interface();
                exit(0);
            }
        } while (++arg_index_count < argc && arg_index_count < 100);
    }else{
        print_man_interface();
        return prompt_interface();
    }
};

static const string_t subset_extract(const string_view_t bytes) noexcept
{
    if (bytes.empty() || bytes.length() > MAX_SUBSET_SIZE || bytes.find("=") == string_t::npos)
        return "";
    return string_t(bytes.substr(bytes.find_last_of("=") + 1));
};

static bool do_execute(const string_view_t message) noexcept
{
    char c;
    std::cout << message << ", continue? [y/n]: ";
    std::cin >> c;
    if ((int)c == 121 || (int)c == 89)
        return true;
    return false;
};

static void print_man() noexcept
{
    std::cout << "\n--------------------------------------------------\n"
                 " Command Line Options\n"
                 " Option         |  Description           | Required\n\n"
                 " --recursive    |  recursive execution   | FALSE\n"
                 " --verbose      |  print console output  | FALSE\n"
                 " --backup       |  create backup before  | FALSE\n"
                 " --backup-path  |  set backup directory  | FALSE\n"
                 " --secret=...   |  [en|de]cryption key   | TRUE\n"
                 " --target=...   |  path target(dir/file) | TRUE\n"
                 " --direct       |  dont ask anything     | FALSE\n"
                 " --encrypt      |  encryption            | OR\n"
                 " --decrypt      |  decryption            | OR\n\n";
};

static void print_man_interface() noexcept
{
    const char *l = FG_COLOR_GREEN, *r = FG_COLOR_CYAN, *z = FG_COLOR_RESET;
    
    std::cout <<   "Command Syntax, set parameter values:\n\n"
                   "\n --------------------------------------------------------------------------------------\n"
                   " OPTION                       ARGS    REQUIRED     DESCRIPTION                          |\n"
                   "                                                                                        |\n"
                 <<l<<" help                      | false "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  print this help screen               "<<z<<"|\n"
                 <<l<<" show                      | false "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  print configuration parameters       "<<z<<"|\n"
                 <<l<<" use-atomic  [true/false]  | true  "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  set/unset (verbose,recursive,direct) "<<z<<"|\n"
                 <<l<<" recursive   [true/false]  | true  "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  set recursive [en/de]cryption        "<<z<<"|\n"
                 <<l<<" verbose     [true/false]  | true  "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  runtime execution ouput              "<<z<<"|\n"
                 <<l<<" backup      [true/false]  | true  "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  create backup before [en/de]decrypt  "<<z<<"|\n"
                 <<l<<" backup-path [...]         | true  "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  set path (dir/file) for backup       "<<z<<"|\n"
                 <<l<<" secret      [...]         | true  "<<z<<"|"<<l<<"  true      "<<z<<"|"<<r<<"  set [en|de]cryption key(7-256)bytes  "<<z<<"|\n"
                 <<l<<" target      [...]         | true  "<<z<<"|"<<l<<"  true      "<<z<<"|"<<r<<"  set path (dir/file) for execution    "<<z<<"|\n"
                 <<l<<" direct      [true/false]  | true  "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  silent mode, don't prompt            "<<z<<"|\n"
                 <<l<<" encrypt    ?[...]         | true  "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  if no arg supplied, encrypt *target* "<<z<<"|\n"
                 <<l<<" decrypt    ?[...]         | true  "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  if no arg supplied, decrypt *target* "<<z<<"|\n"
                 <<l<<" content                  | false "<<z<<"|"<<l<<"  false     "<<z<<"|"<<r<<"  list contents of target path         "<<z<<"|\n\n";
    std::cout << "Examples:\n  set-recursive true\n  set-backup FALSE\n  set-secret secret-key \n  set-target path/to/target  \n\n";
};

static void print_current_conf_parameters() noexcept
{
    const char *l = FG_COLOR_GREEN, *r = FG_COLOR_CYAN, *z = FG_COLOR_RESET;
    std::cout << std::boolalpha<<"\n-------------------------------------------\n"
                 " PARAMETER       REQUIRED    VALUE\n\n"
                 <<l<<" secret_key    |"<<r<<"  true    |  "<<(cli_flags.secret.empty()?"?":cli_flags.secret)<<z<<"\n"
                 <<l<<" recursive     |"<<r<<"  false   |  "<<cli_flags.recursive<<z<<"\n"
                 <<l<<" verbose       |"<<r<<"  false   |  "<<cli_flags.verbose<<z<<"\n"
                 <<l<<" backup        |"<<r<<"  false   |  "<<cli_flags.backup<<z<<"\n"
                 <<l<<" atomic        |"<<r<<"  false   |  "<<cli_flags.atomic_execution<<z<<"\n"
                 <<l<<" backup-path   |"<<r<<"  false   |  "<<(cli_flags.backup_path.empty() ? "?" : cli_flags.backup_path)<<z<<"\n"
                 <<l<<" target        |"<<r<<"  true    |  "<<(cli_flags.target_path.empty() ? "?" : cli_flags.target_path)<<z<<"\n"
                 <<l<<" direct        |"<<r<<"  false   |  "<<cli_flags.direct_execution<<z<<"\n\n";
};

static const string_t prompt_path_to_target() noexcept {
    string_t path;
    std::cout << "Enter Target Path: ";
    std::getline(std::cin, path);
    return path.empty() ? prompt_path_to_target() : path;
};

static const string_t prompt_backup_path() noexcept {
    string_t path;
    std::cout << "Backup Path: ";
    std::getline(std::cin, path);
    return path.empty() ? prompt_path_to_target() : path;
};

static const string_t prompt_secret_key() noexcept {
    string_t key;
    std::cout << "Enter Secret Key[min 8]: ";
    std::getline(std::cin, key);
    return key.length() <= SECRET_BLOCK_SIZE_THRESHOLD ? prompt_secret_key() : key;
};

static void prompt_interface(void) noexcept
{
    string_t command;
    std::cout << FG_COLOR_MAGENTA << "(run) > " << FG_COLOR_RESET;
    std::getline(std::cin, command);
    std::function<bool(const string_view_t &state)> set_boolean_state([=](const string_view_t &state) -> bool {
        if (state.compare("true") == 0 || state.compare("TRUE") == 0)
            return true;
        else if (state.compare("false") == 0 || state.compare("FALSE") == 0)
            return false;
        else
        throw std::invalid_argument("hell no... must B either true or false!");
    });
    try {
    const bool is_valid_command = command.compare("encrypt")==0 || command.compare("decrypt")==0;
    if ((command.compare("quit") == 0 || command.compare("exit") == 0)) 
        exit(0);
    else if(command.empty()) return prompt_interface();
    else if(command.compare("help") == 0){
        print_man_interface();
        return prompt_interface();
    }else if(command.compare("show") == 0){
        print_current_conf_parameters();
        return prompt_interface();
    }
    else if (command.compare("content") == 0){
        show_target_content();
        return prompt_interface();
    }
    else if(!is_valid_command && (command.find_first_of(" ") == string_t::npos || (command.find_last_of(" ") != command.find_first_of(" "))))
        throw std::invalid_argument("no valid command recognized... type exit or quit if u want exit or help for command options screen!");
    
    const string_t command_header(command.substr(0, command.find_first_of(" ")));
    const string_t command_trailer(command.find(" ") != string_t::npos ? command.substr(command.find_first_of(" ") + 1) : "");

    if (command_header.empty())
        return prompt_interface();
    if(command_trailer.empty() && !is_valid_command)
        throw std::invalid_argument("why didn't you supply one value for that option?");
    if (command_header.compare("recursive") == 0)
        cli_flags.recursive = set_boolean_state(command_trailer);
    else if (command_header.compare("verbose") == 0)
        cli_flags.verbose =set_boolean_state(command_trailer);
    else if (command_header.compare("backup") == 0)
        cli_flags.backup = set_boolean_state(command_trailer);
    else if(command_header.compare("backup-path") == 0)
        cli_flags.backup_path = command_trailer.empty() ? prompt_backup_path() : command_trailer;
    else if (command_header.compare("use-atomic") == 0)
        set_atomic_execution(set_boolean_state(command_trailer));
    else if (command_header.compare("secret") == 0)
        cli_flags.secret = command_trailer.length() > SECRET_BLOCK_SIZE_THRESHOLD && command_trailer.length() < SECRET_BLOCK_SIZE_MAX ? command_trailer : cli_flags.secret;
    else if (command_header.compare("target") == 0)
        cli_flags.target_path = command_trailer.length() > 0 && command_trailer.length() < FS_MAX_FILE_NAME_LENGTH ? command_trailer : cli_flags.target_path;
    else if (command_header.compare("direct") == 0)
        cli_flags.direct_execution = set_boolean_state(command_trailer);
    else if (command_header.compare("use-atomic") == 0)
        set_atomic_execution(set_boolean_state(command_trailer));
    else if (command_header.compare("encrypt") == 0){
        cli_flags.mode = OPERATION_MODE::ENCRYPTION;
        cli_flags.target_path = !command_trailer.empty() ? command_trailer : (cli_flags.target_path.empty() ? prompt_path_to_target() : cli_flags.target_path);
        cli_flags.secret = cli_flags.secret.length() <= SECRET_BLOCK_SIZE_THRESHOLD ? prompt_secret_key() : cli_flags.secret;
        if(cli_flags.secret.empty()) 
            throw std::invalid_argument("encryption, no secret key supplied!"); 
        if(cli_flags.target_path.empty()) 
            throw std::invalid_argument("encryption, no target specified!");  
        execute_command();
        return prompt_interface();
    }
    else if (command_header.compare("decrypt") == 0){
        cli_flags.mode = OPERATION_MODE::DECRYPTION;
        cli_flags.target_path = (command_trailer.empty() && cli_flags.target_path.empty()) ? prompt_path_to_target() : cli_flags.target_path;
        cli_flags.secret = cli_flags.secret.length() <= SECRET_BLOCK_SIZE_THRESHOLD ? prompt_secret_key() : cli_flags.secret;
        if(cli_flags.secret.empty()) 
            throw std::invalid_argument("decryption, no secret key supplied!"); 
        if(cli_flags.target_path.empty()) 
            throw std::invalid_argument("decryption, no target specified!");  
        execute_command();
        return prompt_interface();
    }
    else if(command_header.compare("show") == 0)
    {
        print_current_conf_parameters();
        return prompt_interface();
    }
    else if (command_header.compare("exit") == 0 || command_header.compare("quit") == 0)
        return;
    else // command unrecognized...
        return prompt_interface();
    }catch(const std::invalid_argument& e){ // did you read the argument list options? looks like you didn't... don't fuck this up and read them please!
        std::cout << "Command Not Recognized: " << e.what() << "\n";
    }catch(const std::runtime_error& e){ // runtime error? not that bad...
        std::cout << "Ops, something bad happened during runtime execution: " << e.what() << '\n';
    }catch(const std::exception& e){ // better to exit at this point, something serious catched, maybe unrecoverable?
        std::cout <<"Something Really Fuc**d... this is what happened: " << e.what() << "\n...bye\n";
        std::exit(0);
    }
    return prompt_interface();
};

static void execute_command(void) {
    FSController<string_t> *fController = new (std::nothrow)FSController<string_t>;
    ByteCrypt *BC = new (std::nothrow)ByteCrypt;
    try
    {
        if (!cli_flags.direct_execution)
            if (!do_execute("Setting " + cli_flags.target_path + " as target path..."))
                return;
        if (cli_flags.backup)
        {
            if(cli_flags.backup_path.empty())
                cli_flags.backup_path = prompt_backup_path();
            if (fController->IsDirectory(cli_flags.target_path))
            {
                // create backup in the same directory
                if (!fController->CreateDirectoryBackupJoinExecution(cli_flags.target_path, cli_flags.backup_path, true, true, true))
                    throw std::runtime_error("Cannot create backup directory, aborting this fucking operation for your safety!");
            }
            else if (fController->FileExists(cli_flags.target_path))
            {
                const string_t read_file(fController->FileRead(cli_flags.target_path).file_content);
                if (read_file.empty())
                    throw std::runtime_error("Backup file, but file is empty, wtf...");
                fController->FileWrite(string_t("BACKUP.txt"), read_file, true);
            }
        }
        if (fController->IsTextFile(cli_flags.target_path))
            encrypt_file(fController, BC);
        else if (fController->IsDirectory(cli_flags.target_path))
            encrypt_directory(fController, BC);
    }
    catch (const std::invalid_argument &e)
    {
        std::cout << FG_COLOR_YELLOW << "[!] Invalid Argument Value: " << e.what() << FG_COLOR_RESET << "\n";
        return;
    }
    catch (const std::runtime_error &e)
    {
       std::cout << FG_COLOR_YELLOW << "[!] Runtime Error: " << e.what() << FG_COLOR_RESET << "\n";
        return;
    }
    catch (const std::exception &e)
    {
        std::cout << FG_COLOR_RED << "[!] Fatal Exception: " << e.what() << FG_COLOR_RESET << "\n";
    }
    delete fController;
    delete BC;
    return;
};


void set_atomic_execution(const bool mode) noexcept{
    cli_flags.direct_execution = mode;
    cli_flags.verbose = !mode;
    cli_flags.atomic_execution = mode;
};

void encrypt_directory(FSController<string_t> *fsi, ByteCrypt *bci)
{
    if(fsi == nullptr || bci == nullptr) return;
    const stDirectoryCollectionStat dir_aggregation = fsi->CollectDirectoryEntriesWithProfiling(cli_flags.target_path, true);
    if (dir_aggregation.registry_size == 0)
        return;
    if (cli_flags.mode == OPERATION_MODE::ENCRYPTION)
    {
        for (const string_t &entry : dir_aggregation.registry)
        {
            const stFileDescriptor f_description = fsi->FileRead(entry);
            if (f_description.file_size > DESCRIPTOR_SIZE_THRESHOLD)
            {
                if (!cli_flags.direct_execution)
                    if (!do_execute("encrypting content of " + entry))
                        return;
                const encryption_result encrypted = bci->gcm_encrypt(f_description.file_content, cli_flags.secret, e_gcm_algorithm::AES);
                if (encrypted.error.has_error)
                    throw std::runtime_error(encrypted.error.error_msg);
                fsi->FileWrite(entry, encrypted.result);
                if (cli_flags.verbose)
                    std::cout << "File <" << entry << "> has been encrypted!\n";
            }
        }
    }
    else
    {
        for (const string_t &entry : dir_aggregation.registry)
        {
            const stFileDescriptor f_description = fsi->FileRead(entry);
            if (f_description.file_size > DESCRIPTOR_SIZE_THRESHOLD)
            {
                if (!cli_flags.direct_execution)
                    if (!do_execute("decrypting content of " + entry))
                        return;
                const decryption_result decrypted = bci->gcm_decrypt(f_description.file_content, cli_flags.secret, e_gcm_algorithm::AES);
                if (decrypted.error.has_error)
                    throw std::runtime_error(decrypted.error.error_msg);
                fsi->FileWrite(entry, decrypted.result);
                if (cli_flags.verbose)
                    std::cout << "Entry <" << entry << "> has been decrypted!\n";
            }
        }
    }
};

void encrypt_file(FSController<string_t> *fsi, ByteCrypt *bci)
{
    if (fsi == nullptr || bci == nullptr)
        return;
    const stFileDescriptor description(fsi->FileRead(cli_flags.target_path, false));
    if (description.file_size > 0)
    {
        if (cli_flags.mode == OPERATION_MODE::ENCRYPTION)
        {
            if (!cli_flags.direct_execution)
                if (!do_execute("encrypting " + cli_flags.target_path))
                    return;
            const encryption_result encrypted = bci->gcm_encrypt(description.file_content, cli_flags.secret, e_gcm_algorithm::AES);
            fsi->FileWrite(cli_flags.target_path, encrypted.result, false);
            if (cli_flags.verbose)
            {
                std::cout << "File <" << cli_flags.target_path << "> has been encrypted!\n";
                return;
            }
        }
        else
        {
            if (!cli_flags.direct_execution)
                if (!do_execute("decrypting " + cli_flags.target_path))
                    return;
            const decryption_result decrypted = bci->gcm_decrypt(description.file_content, cli_flags.secret, e_gcm_algorithm::AES);
            fsi->FileWrite(cli_flags.target_path, decrypted.result, false);
            if (cli_flags.verbose)
            {
                std::cout << "File <" << cli_flags.target_path << "> has been decrypted!\n";
                return;
            }
        }
    }
};

inline static void show_target_content() {
    if(cli_flags.target_path.empty()) {
        std::cout << "nothing to show...\n";
    }else{
        if(FSController<string_t>::IsDirectory(cli_flags.target_path)){
            FSController FSC;

            const std::vector<string_t> directory_blocks(FSC.CollectDirectoryEntries(cli_flags.target_path, true));
            if(directory_blocks.size() > 0){
                for(const auto& block: directory_blocks){
                    std::this_thread::sleep_for(std::chrono::microseconds(900));
                    std::cout << "[/] " << block << "\n";
                }
            }
        }
    }
};
