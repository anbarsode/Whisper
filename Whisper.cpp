#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <math.h>
#include <assert.h>
#include <string.h>
#include <iomanip>
#include <Windows.h>
#include <vector>

void show_help(std::string err_msg) //Usage help
{
    std::cout << err_msg;
    std::string helptxt("\
    \nUsage\n\
    \nTo encrypt/decrypt files interactively:\
         \n\tenter '$ Whisper' without arguments\
         \n\tor double click on 'Whisper.exe' from file explorer\
    \n\nTo encrypt a single file, enter\
         \n\t$ Whisper e dir/file/to/encrypt dir/name/of/encrypted/file\
    \nTo decrypt a single file, enter\
         \n\t$ Whisper d dir/file/to/decrypt dir/name/of/decrypted/file\
    \n\nTo encrypt all files listed in a text file (One pair per line of in/out file names, separated by tab.), enter\
         \n\t$ Whisper f e dir/file/containing/filename/list\
    \nTo decrypt all files listed in a text file (One pair per line of in/out file names, separated by tab.), enter\
         \n\t$ Whisper f d dir/file/containing/filename/list\
    \n\nTo encrypt all files in folder 'dir1' and save the encrypted files to 'dir2', enter\
         \n\t$ Whisper a e dir1 dir2\
    \nTo decrypt all files in folder 'dir1' and save the decrypted files to 'dir2', enter\
         \n\t$ Whisper a d dir1 dir2"\
    );
    std::cout << helptxt << std::endl;
}

//limits on various parameters. Note that the usual logistic growth equation has p=1, q=1
float pmin = 0.5, pmax = 1.25, qmin = 0.5, qmax = 1.25, gmin = 0.1, gmax = 0.4, rwidth = 0.05;

typedef struct //holds parameters that generate the encrypting polynomial
{
    int num_coef;
    int t[11];
    float gamma, x[11], p[11], q[11], r[11], y[11];
}key_data;

float find_rmax(float p, float q) //Finding the maximum value of growth rate that avoids blowup
{
    return pow(p+q,p+q) / pow(p,p) / pow(q,q);
}

float iterfunc(float x, float p, float q, float r) //Logistic growth iteration
{
    return r * pow(x,p) * pow((1-x),q);
}

key_data get_key_data(bool enc) //Key expansion: takes a char key and converts it to parameters that generate the encrypting polynomial
{
    //getting char key from user
    std::string char_key;
    if(enc) std::cout << "Create a password (14-64 characters without white spaces):" << std::endl;
    else std::cout << "Password:" << std::endl;
    std::cin >> char_key;
    
    //getting bitkey
    std::string bitkey("");
    for(int j=0; j < char_key.length(); j++)
        for(int i=7; i >= 0; i--)
            bitkey += ((char_key[j] >> i) & 1);
    
    //getting gamma
    int j = 0, spacing = ((1 + bitkey.length()) / 16) - 1;
    float gamma = 0.0;
    for(int i = spacing; i < 17 * spacing; i+=spacing)
    {
        gamma += pow(2,16-i/spacing) * int(bitkey[i-j]) / 65536;
        bitkey.erase(bitkey.begin()+i-j);
        j++;
    }
    gamma = gmin + (gmax - gmin) * gamma;
    
    //setting up key data
    key_data key;
    key.gamma = gamma;
    key.num_coef = (int) ceil(bitkey.length() / 48);
    int t_bits = bitkey.length() / 6 / key.num_coef;
    if((bitkey.length() - key.num_coef * t_bits) % (key.num_coef * 4) != 0)
        for(int i=0; i < ((bitkey.length() - key.num_coef * t_bits) % (key.num_coef * 4)); i++)
            bitkey.insert(bitkey.length()/2,"\x01");
    int x_bits = (bitkey.length() - key.num_coef * t_bits) / (key.num_coef * 4);
    
    //getting t
    for(int k=0; k < key.num_coef; k++)
    {
        j = 0;
        spacing = ((1 + bitkey.length()) / t_bits) - 1;
        int t = 0;
        for(int i=spacing; i < (t_bits + 1) * spacing; i+=spacing)
        {
            t += pow(2,t_bits-i/spacing) * int(bitkey[i-j]);
            bitkey.erase(bitkey.begin()+i-j);
            j++;
        }
        key.t[k] = t;
    }
    
    //getting x,p,q,r
    for(int k=0; k < key.num_coef; k++)
    {
        float x=0, p=0, q=0, r=0, max_int_div = pow(2,-x_bits);
        for(int i=0; i < x_bits; i++)
        {
            x += pow(2,x_bits-i-1) * int(bitkey[4*x_bits*k + 4*i]) * max_int_div;
            p += pow(2,x_bits-i-1) * int(bitkey[4*x_bits*k + 4*i + 1]) * max_int_div;
            q += pow(2,x_bits-i-1) * int(bitkey[4*x_bits*k + 4*i + 2]) * max_int_div;
            r += pow(2,x_bits-i-1) * int(bitkey[4*x_bits*k + 4*i + 3]) * max_int_div;
        }
        assert((x<1) && (p<1) && (q<1) && (r<1));
        p = pmin + (pmax - pmin) * p;
        q = qmin + (qmax - qmin) * q;
        r = find_rmax(p,q) * (1 - rwidth * r);
        key.x[k] = x;
        key.p[k] = p;
        key.q[k] = q;
        key.r[k] = r;
    }
    
    //initializing y
    for(int i=0; i<key.num_coef; i++)
    {
        key.y[i] = key.x[i];
        for(int j=0; j < key.t[i]; j++)
            key.y[i] = iterfunc(key.y[i], key.p[i], key.q[i], key.r[i]);
    }
    return key;
}
        
float forward_polynomial(unsigned char c, int num_coef, float gamma, float y[11], float norm) //Encrypting a character
{
    float f = pow(c / 256.0, gamma);
    f = f * y[0] + y[1];
    for(int i=2; i<num_coef; i++)
        f = pow(f, i / (double) (i-1)) + y[i];
    f /= norm; //normalization
    return f;
}

unsigned char backward_polynomial(float f, int num_coef, float gamma, float y[11], float norm) //Decrypting a character
{
    f *= norm; //reversing normalization
    for(int i=num_coef-1; i>1; i--)
        f = pow(f - y[i], (i-1) / (double) i);
    f = (f - y[1]) / y[0];
    f = pow(f, 1/gamma) * 256.0;
    return round(f);
}

float find_normalization(int num_coef) //Calculating normalization to keep floats between 0 and 1
{
    float norm = 2;
    for(int i=2; i < num_coef; i++)
        norm = pow(norm, i / (double) (i-1)) + 1;
    return norm;
}

std::string float_to_bigbyte(float f, int num_bytes, long mult) //Writing a given float in base 256 instead of 10
{
    std::string bigbyte("");
    long num = round(f * mult);
    for(int i=0; i < num_bytes; i++)
    {
        bigbyte += (char) num % 256;
        num /= 256;
    }
    return bigbyte;
}

float bigbyte_to_float(std::string bigbyte, int num_bytes, float multinv) //Reading a base 256 number string as a float
{
    float f = 0;
    for(int i=0; i < num_bytes; i++)
        f += pow(256, i) * multinv * (unsigned char) bigbyte[i];
    return f;
}


void encrypt_single(char* clear_file, char* cipher_file, bool use_big_byte, key_data key) //Single file encryption
{
    int num_bytes = ceil((4 + key.num_coef) * log(10) / log(256));
    long mult = pow(256, num_bytes);
    float mb_size = 1 / 1024.0 / 1024.0;
    long progress = 0;
    
    std::ifstream f(clear_file, std::ios::binary | std::ios::in);
    std::ofstream g(cipher_file, std::ios::binary | std::ios::out);
    assert(f.is_open());
    assert(g.is_open());
    
    float norm = find_normalization(key.num_coef);
    
    std::string namestr("");
    namestr = clear_file;
    int name_len = namestr.length();
    if(name_len > 100) std::cout << "Input file's name is too large (limit: 100 characters)" << std::endl;
    for(int i=0; i<(99 - name_len); i++) namestr += " "; namestr += "\n";
    
    char c;
    //write (encrypted) name of the original file at the beginning of the encrypted file
    for(int j=0; j<100; j++)
    {
        c = namestr[j];
        if(use_big_byte) g << float_to_bigbyte(forward_polynomial(c, key.num_coef, key.gamma, key.y, norm), num_bytes, mult);
        else g << " " << std::setprecision(4 + key.num_coef) << std::fixed << forward_polynomial(c, key.num_coef, key.gamma, key.y, norm);
        for(int i=0; i<key.num_coef; i++)
            key.y[i] = iterfunc(key.y[i], key.p[i], key.q[i], key.r[i]);
    }
    //write actual data
    while(f.get(c))
    {
        if(use_big_byte) g << float_to_bigbyte(forward_polynomial(c, key.num_coef, key.gamma, key.y, norm), num_bytes, mult);
        else g << " " << std::setprecision(4 + key.num_coef) << std::fixed << forward_polynomial(c, key.num_coef, key.gamma, key.y, norm);
        for(int i=0; i<key.num_coef; i++)
            key.y[i] = iterfunc(key.y[i], key.p[i], key.q[i], key.r[i]);
        progress ++;
        if(progress % 10485760 == 0) std::cout << progress * mb_size << " mb encrypted" << std::endl;
    }
    f.close();
    g.close();
    std::cout << "File '" << clear_file << "' encrypted to '" << cipher_file << "'." << std::endl;
}

void decrypt_single(char* cipher_file, char* clear_file, bool use_big_byte, key_data key) //single file decryption
{
    int num_bytes = ceil((4 + key.num_coef) * log(10) / log(256));
    float multinv = pow(256, -num_bytes);
    float mb_size = 1 / 1024.0 / 1024.0;
    long progress = 0;
    
    std::ifstream f(cipher_file, std::ios::binary | std::ios::in);
    std::ofstream g(clear_file, std::ios::binary | std::ios::out);
    assert(f.is_open());
    assert(g.is_open());
    
    float norm = find_normalization(key.num_coef);
    
    float a;
    char c;
    //read name data
    std::cout << "\nOriginal file was:\n\t";
    for(int j=0; j<100; j++)
    {
        if(use_big_byte)
        {
            std::string s("");
            for(int i=0; i<num_bytes; i++)
                if(f.get(c)) s += c;
                else if(i>0) std::cout << "Encrypted file is possibly currupt.";
                else break;
            if(!f.eof()) std::cout << backward_polynomial(bigbyte_to_float(s, num_bytes, multinv), key.num_coef, key.gamma, key.y, norm);
        }
        else
        {
            f >> a;
            std::cout << backward_polynomial(a, key.num_coef, key.gamma, key.y, norm);
        }
        for(int i=0; i<key.num_coef; i++)
            key.y[i] = iterfunc(key.y[i], key.p[i], key.q[i], key.r[i]);
    }
    std::cout << std::endl;
    
    //read actual data
    do
    {
        if(use_big_byte)
        {
            std::string s("");
            for(int i=0; i<num_bytes; i++)
                if(f.get(c)) s += c;
                else if(i>0) std::cout << "Encrypted file is possibly currupt.";
                else break;
            if(!f.eof()) g.put(backward_polynomial(bigbyte_to_float(s, num_bytes, multinv), key.num_coef, key.gamma, key.y, norm));
        }
        else
        {
            f >> a;
            g << backward_polynomial(a, key.num_coef, key.gamma, key.y, norm);
        }
        for(int i=0; i<key.num_coef; i++)
            key.y[i] = iterfunc(key.y[i], key.p[i], key.q[i], key.r[i]);
        progress ++;
        if(progress % 10485760 == 0) std::cout << progress * mb_size << " mb decrypted" << std::endl;
    }while(!f.eof());
    f.close();
    g.close();
    std::cout << "\nFile " << cipher_file << " decrypted to " << clear_file << std::endl;
}

//taken from https://stackoverflow.com/questions/612097/how-can-i-get-the-list-of-files-in-a-directory-using-c-or-c
std::vector<std::string> get_all_files_names_within_folder(std::string folder) //a c++ 'ls' for Windows
{
    std::vector<std::string> names;
    std::string search_path = folder + "/*.*";
    WIN32_FIND_DATA fd; 
    HANDLE hFind = ::FindFirstFile(search_path.c_str(), &fd); 
    if(hFind != INVALID_HANDLE_VALUE) { 
        do { 
            // read all (real) files in current folder
            // , delete '!' read other 2 default folder . and ..
            if(! (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ) {
                names.push_back(fd.cFileName);
            }
        }while(::FindNextFile(hFind, &fd)); 
        ::FindClose(hFind); 
    } 
    return names;
}

//taken from https://stackoverflow.com/questions/40337177/c-how-to-use-fstream-to-read-tab-delimited-file-with-spaces
void split(const std::string &s, char delim, std::vector<std::string> &elems) //splitting a line into substrings separated by a delimiter
{
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim))
    {
        elems.push_back(item);
    }
}

int main(int argc, char** argv)
{
    bool use_big_byte = true;
    
    if(argc == 1) //Interactive mode
    {
        char mode, individual_passwords, quit;
        do{
            std::cout << "Encrypt or Decrypt? (e/d)" << std::endl;
            std::cin >> mode;
        }while((mode != 'e') && (mode != 'd'));
        
        do
        {
            std::cout << "Use individual passwords? (y/n)" << std::endl;
            std::cin >> individual_passwords;
        }while((individual_passwords != 'y') && (individual_passwords != 'n'));
        
        key_data key;
        if(individual_passwords == 'n') key = get_key_data((mode == 'e')?true:false); //take password only once if not individual_passwords
        
        do
        {
            if(individual_passwords == 'y') key = get_key_data((mode == 'e')?true:false); //take individual passowrds for every file
            std::string clear_file, cipher_file;
            char cl[100], ci[100];
            
            if(mode == 'e')
            {
                std::cout << "Enter name of file to be encrypted: \n";
                std::cin.ignore();
                std::getline(std::cin, clear_file);
                std::cout << "Enter name of the created encrypted file: \n";
                std::getline(std::cin, cipher_file);
                strcpy(cl, clear_file.c_str());
                strcpy(ci, cipher_file.c_str());
                encrypt_single(cl, ci, use_big_byte, key);
            }
            
            else if(mode == 'd')
            {
                std::cout << "Enter name of file to be decrypted: \n";
                std::cin.ignore();
                std::getline(std::cin, cipher_file);
                std::cout << "Enter name of the created decrypted file: \n";
                std::getline(std::cin, clear_file);
                strcpy(ci, cipher_file.c_str());
                strcpy(cl, clear_file.c_str());
                decrypt_single(ci, cl, use_big_byte, key);
            }
            
            std::cout << "\nQuit? (y/n)" << std::endl;
            std::cin >> quit;
        }while(quit != 'y');
    }
    
    else if(argv[1][0]=='e') //single file encryption
    {
        key_data key;
        key = get_key_data(true);
        encrypt_single(argv[2], argv[3], use_big_byte, key);
    }
        
    else if(argv[1][0]=='d') //single file decryption
    {
        key_data key;
        key = get_key_data(false);
        decrypt_single(argv[2], argv[3], use_big_byte, key);
    }
        
    else if(argv[1][0]=='f') //inputs taken from file
    {
        char mode, individual_passwords;
        if(argv[2][0]=='e') mode = 'e';
        else if(argv[2][0]=='d') mode = 'd';
        else show_help("Error: Invalid mode. (Should be e/d)\n");
        
        do
        {
            std::cout << "Use individual passwords? (y/n)" << std::endl;
            std::cin >> individual_passwords;
        }while((individual_passwords != 'y') && (individual_passwords != 'n'));
        
        key_data key;
        if(individual_passwords == 'n') key = get_key_data((mode == 'e')?true:false);
        
        std::ifstream f(argv[3]);
        std::string line;
        
        if(mode=='e')
            while(std::getline(f, line))
            {
                if(individual_passwords == 'y') key = get_key_data((mode == 'e')?true:false);
                std::vector<std::string> file_names;
                split(line, '\t', file_names);
                char clear_file[100], cipher_file[100];
                strcpy(clear_file, (file_names[0]).c_str());
                strcpy(cipher_file, (file_names[1]).c_str());
                encrypt_single(clear_file, cipher_file, use_big_byte, key);
            }
        
        else if(mode=='d')
            while(std::getline(f, line))
            {
                if(individual_passwords == 'y') key = get_key_data((mode == 'e')?true:false);
                std::vector<std::string> file_names;
                split(line, '\t', file_names);
                char cipher_file[100], clear_file[100];
                strcpy(cipher_file, (file_names[0]).c_str());
                strcpy(clear_file, (file_names[1]).c_str());
                decrypt_single(cipher_file, clear_file, use_big_byte, key);
            }
    }
        
    else if(argv[1][0]=='a') //all files in a folder
    {
        char mode, individual_passwords;
        if(argv[2][0]=='e') mode = 'e';
        else if(argv[2][0]=='d') mode = 'd';
        else show_help("Error: Invalid mode. (Should be e/d)\n");
        
        do
        {
            std::cout << "Use individual passwords? (y/n)" << std::endl;
            std::cin >> individual_passwords;
        }while((individual_passwords != 'y') && (individual_passwords != 'n'));
        
        key_data key;
        if(individual_passwords == 'n') key = get_key_data((mode == 'e')?true:false);
        
        std::vector<std::string> file_names;
        file_names = get_all_files_names_within_folder(argv[3]);
        
        if(mode=='e')
            for(int i=0; i < file_names.size(); i++)
            {
                file_names[i].insert(0, "\\");
                if(individual_passwords == 'y') key = get_key_data((mode == 'e')?true:false);
                char clear_file[100], cipher_file[100];
                strcpy(clear_file, (argv[3] + file_names[i]).c_str());
                strcpy(cipher_file, (argv[4] + file_names[i] + ".encrypted").c_str());
                encrypt_single(clear_file, cipher_file, use_big_byte, key);
            }
            
        else if(mode=='d')
            for(int i=0; i < file_names.size(); i++)
            {
                file_names[i].insert(0, "\\");
                if(individual_passwords == 'y') key = get_key_data((mode == 'e')?true:false);
                char clear_file[100], cipher_file[300];
                strcpy(cipher_file, (argv[3] + file_names[i]).c_str());
                strcpy(clear_file, (argv[4] + file_names[i] + ".decrypted").c_str());
                decrypt_single(cipher_file, clear_file, use_big_byte, key);
            }
    }
        
    else show_help("Error: Invalid arguments\n"); //can't you give one simple combination of characters dude?
}
