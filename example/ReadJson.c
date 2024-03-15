#include "ReadJson.h"
#include "../json-c/include/json-c/json.h"
#include "reader_util.h"

#define MAX_PATH_LENGTH 256

// Array to store SkipParameters
struct SkipParameters* paramsVector = NULL;
int vectorSize = 0;

// Define a structure to represent skipParameters
struct SkipParameters 
{
    char* sourceIP;
    char* destinationIP;
    int destinationPort; // Use -1 if not present
};

/*--------------------------------------------------------------------------------------------------------------------------*/
static void getProgramFolderPath(char* buffer, size_t size) 
{
    // Get the folder path of the currently running program
    char* end;
    size_t length;

#ifdef _WIN32
    GetModuleFileName(NULL, buffer, size);
    end = strrchr(buffer, '\\');
#else
    if (readlink("/proc/self/exe", buffer, size) == -1) {
        perror("readlink");
        exit(EXIT_FAILURE);
    }
    end = strrchr(buffer, '/');
#endif

    if (end == NULL) {
        fprintf(stderr, "Error: Unable to determine program folder path.\n");
        exit(EXIT_FAILURE);
    }

    length = (size_t)(end - buffer);
    buffer[length] = '\0';  // Null-terminate the string
}

/*--------------------------------------------------------------------------------------------------------------------------*/
static void appendFileNameToPath(const char* file_name, const char* folder_path, char* output_path, size_t size) 
{
    // Join the file name with the folder path
#ifdef _WIN32
    snprintf(output_path, size, "%s\\%s", folder_path, file_name);
#else
    snprintf(output_path, size, "%s/%s", folder_path, file_name);
#endif
}


/*--------------------------------------------------------------------------------------------------------------------------*/
// Function to traverse JSON and create an array of SkipParameters
static void traverseJsonObject(json_object* jsonObj, struct SkipParameters** paramsVector, int* vectorSize)
{
    json_object_object_foreach(jsonObj, key, val) {
        enum json_type type = json_object_get_type(val);

        if (type == json_type_object)
        {
            traverseJsonObject(val, paramsVector, vectorSize);
        }
        else if (type == json_type_array)
        {
            int arrayLength = json_object_array_length(val);

            for (int i = 0; i < arrayLength; ++i)
            {
                *vectorSize += 1;
                *paramsVector = realloc(*paramsVector, (*vectorSize) * sizeof(struct SkipParameters));
                (*paramsVector)[*vectorSize - 1].sourceIP = _strdup("NOT_SET");
                (*paramsVector)[*vectorSize - 1].destinationIP = _strdup("NOT_SET");
                (*paramsVector)[*vectorSize - 1].destinationPort = -1;

                json_object* arrayElement = json_object_array_get_idx(val, i);
                traverseJsonObject(arrayElement, paramsVector, vectorSize);
            }
        }
        else
        {
            if (type == json_type_string)
            {
                // Assume string key, add your own logic if it's different
                const char* keyStr = key;
                const char* valueStr = json_object_get_string(val);

                // Check if key is one of the desired parameters
                if (strcmp(keyStr, "sourceIP") == 0)
                {
                    char* sourceIP = _strdup(valueStr);
                    (*paramsVector)[*vectorSize - 1].sourceIP = sourceIP;
                }

                // Check if key is one of the desired parameters
                if (strcmp(keyStr, "destinationIP") == 0)
                {
                    char* destinationIP = _strdup(valueStr);
                    (*paramsVector)[*vectorSize - 1].destinationIP = destinationIP;
                }

            }
            else if (type == json_type_int)
            {
                // Assume string key, add your own logic if it's different
                const char* keyStr = key;
                int destinationPort = json_object_get_int(val);

                (*paramsVector)[*vectorSize - 1].destinationPort = destinationPort;
            }
        }
    }
}

/*--------------------------------------------------------------------------------------------------------------------------*/
extern void freeJsonLogFileData()
{
    // Free allocated memory
    for (int i = 0; i < vectorSize; ++i)
    {
        free(paramsVector[i].sourceIP);
        free(paramsVector[i].destinationIP);
    }

    free(paramsVector);
}

/*--------------------------------------------------------------------------------------------------------------------------*/
static bool matchEntryInParamsVector(const char* srcIP, const char* destIP, int destPort) 
{
    for (int i = 0; i < vectorSize; ++i) 
    {
        // Check if sourceIP matches
        if (strcmp(paramsVector[i].sourceIP, "NOT_SET") != 0 && strcmp(paramsVector[i].sourceIP, srcIP) != 0) 
        {
            continue;
        }

        // Check if destinationIP matches
        if (strcmp(paramsVector[i].destinationIP, "NOT_SET") != 0 && strcmp(paramsVector[i].destinationIP, destIP) != 0) 
        {
            continue;
        }

        // Check if destinationPort matches (if present)
        if (paramsVector[i].destinationPort != -1 && paramsVector[i].destinationPort != destPort) 
        {
            continue;
        }

        // All criteria match, return true
        return true;
    }

    // No matching entry found
    return false;
}

/*--------------------------------------------------------------------------------------------------------------------------*/
static void printParamsVector(const struct SkipParameters* paramsVector, int vectorSize)
{
    printf("Params Vector:\n");

    for (int i = 0; i < vectorSize; ++i) {
        printf("Entry %d:\n", i + 1);
        printf("  Source IP: %s\n", paramsVector[i].sourceIP);
        printf("  Destination IP: %s\n", paramsVector[i].destinationIP);

        if (paramsVector[i].destinationPort != -1) 
        {
            printf("  Destination Port: %d\n", paramsVector[i].destinationPort);
        }
        else 
        {
            printf("  Destination Port: Not present\n");
        }

        printf("\n");
    }
}

/*--------------------------------------------------------------------------------------------------------------------------*/
extern bool isValidFlowForLogging(struct ndpi_flow_info* flow)
{
    static hasAlreadyReadLogFile = false;
    if (!hasAlreadyReadLogFile)
    {
        char buffer[1024];
        const char* configurationFileName = "Settings\\nDPIConfiguration.json";

        // Get the folder path of the currently running program
        char programFolderPath[MAX_PATH_LENGTH];
        getProgramFolderPath(programFolderPath, sizeof(programFolderPath));

        // Append the file name to the folder path
        char configurationFilePath[MAX_PATH_LENGTH];
        appendFileNameToPath(configurationFileName, programFolderPath, configurationFilePath, sizeof(configurationFilePath));
        printf("\nConfiguration file location: %s\n", configurationFilePath);

        FILE* fp = fopen(configurationFilePath, "r");
        if (fp == NULL)
        {
            perror("Error opening file");
            return 1;
        }

        // Get the file size
        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        rewind(fp);

        // Read the file into a buffer
        fread(buffer, 1024, 1, fp);
        fclose(fp);

        // Parse the JSON buffer
        struct json_object* root;
        root = json_tokener_parse(buffer);
        if (root == NULL)
        {
            fprintf(stderr, "Error parsing JSON\n");
            return 1;
        }

        // Traverse the JSON object and populate the array
        traverseJsonObject(root, &paramsVector, &vectorSize);
        printParamsVector(paramsVector, vectorSize);

        // Free the JSON object
        json_object_put(root);
        hasAlreadyReadLogFile = true;
    }

    char src_name[INET6_ADDRSTRLEN] = { '\0' };
    if (flow->ip_version == 4)
    {
        inet_ntop(AF_INET, &flow->src_ip, src_name, sizeof(src_name));
    }
    else
    {
        inet_ntop(AF_INET6, &flow->src_ip6, src_name, sizeof(src_name));
    }

    char dst_name[INET6_ADDRSTRLEN] = { '\0' };
    if (flow->ip_version == 4)
    {
        inet_ntop(AF_INET, &flow->dst_ip, dst_name, sizeof(dst_name));
    }
    else
    {
        inet_ntop(AF_INET6, &flow->dst_ip6, dst_name, sizeof(dst_name));
    }

    int destinationPort = flow->dst_port;
    u_int32_t destinationPortToCompare = ntohs(destinationPort);

    return !matchEntryInParamsVector(src_name, dst_name, destinationPortToCompare);
}