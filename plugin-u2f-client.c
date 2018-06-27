#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/wait.h>

#include "openvpn-plugin.h"

#include <curl/curl.h>
#include "u2f-host.h"

#define U2F_CLIENT_PLUGIN_NAME "u2f-client"

struct MemoryStruct {
    char *memory;
    size_t size;
};

struct u2f_client_context
{
    struct openvpn_plugin_callbacks *global_vtab;
};

static const char *
get_env(const char *name, const char *envp[])
{
    if (envp)
    {
        int i;
        const int namelen = (int)strlen(name);
        for (i = 0; envp[i]; ++i)
        {
            if (!strncmp(envp[i], name, namelen))
            {
                const char *cp = envp[i] + namelen;
                if (*cp == '=')
                {
                    return cp + 1;
                }
            }
        }
    }
    return NULL;
}

static void
u2f_client_log(struct u2f_client_context *ctx,
               openvpn_plugin_log_flags_t flags, const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    ctx->global_vtab->plugin_vlog(flags, U2F_CLIENT_PLUGIN_NAME, fmt, va);
    va_end(va);
}

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    
    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if(mem->memory == NULL) {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}

int do_auth_request(u2fh_devs *devs, const char *username, const char *password, const char *txid, const char *origin, const char **error, int register_first)
{
    long http_result;
    char *register_challenge;
    char *auth_challenge;
    
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */
    
    CURL *curl=curl_easy_init();
    if(!curl)
    {
        free(chunk.memory);
        curl_easy_cleanup(curl);
        *error = "Could not initialize libcurl";
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    /*
     * Endpoints for 2F server
     *
     * GET /auth/:id
     *   200, body: (JSON blob) - challenge being provided
     *   204 - no second factor, already okay
     *   303 → registration endpoint - in-band registration required
     *   ??? - out-of-band registration required
     *   (in 4xx because the client itself can't continue or retry)
     *   4xx - bad txn ID or other request problems
     *   5xx - broken
     *
     * POST /auth/:id, body: (JSON blob with response)
     *   202 - OK
     *   403 - bad response
     *   4xx - other request problems
     *   5xx - broken
     *
     * GET /register/:id
     *   200, body: (JSON blob) - challenge being provided
     *   204 - already registered, no challenge available
     *   4xx - bad txn ID or other request problems
     *   5xx - broken
     *
     * POST /register/:id, body:(JSON blob with response)
     *   202 - OK
     *   403 - bad response
     *   4xx - other request problems
     *   5xx - broken
     *
     */
    
    char url[1024];
    
    if(register_first)
    {
        sprintf(url, "https://%s/register/%s", origin, txid);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        
        CURLcode curl_result=curl_easy_perform(curl);
        if(curl_result!=CURLE_OK)
        {
            free(chunk.memory);
            curl_easy_cleanup(curl);
            *error = "Error from libcurl";
            return OPENVPN_PLUGIN_FUNC_ERROR;
        }
        
        
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_result);
        switch(http_result)
        {
            case 200:
                /* 200, body: (JSON blob) - challenge being provided */
                // Convert to null-terminated string
                register_challenge=malloc(chunk.size+1);
                memcpy(register_challenge, chunk.memory, chunk.size);
                memset(register_challenge, 0, chunk.size);
                
                char response[2048];
                size_t response_len = sizeof (response);
                
                u2fh_rc result = u2fh_register2(devs, register_challenge, origin,
                                                response, &response_len,
                                                U2FH_REQUEST_USER_PRESENCE);
                free(register_challenge);
                
                if(result != U2FH_OK)
                {
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    return OPENVPN_PLUGIN_FUNC_ERROR;
                }
                
                // Convert to null-terminated string
                memset(response, 0, response_len);
                
                sprintf(url, "https://%s/register/%s", origin, txid);
                curl_easy_setopt(curl, CURLOPT_URL, url);
                curl_easy_setopt(curl, CURLOPT_POST, 1);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, response);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, response_len);
                
                curl_result=curl_easy_perform(curl);
                if(curl_result!=CURLE_OK)
                {
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    *error = "Error from libcurl";
                    return OPENVPN_PLUGIN_FUNC_ERROR;
                }
                
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_result);
                switch(http_result)
            {
                case 202:
                    /* 202 - OK */
                    break;
                case 403:
                    /* 403 - bad response */
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    return OPENVPN_PLUGIN_FUNC_ERROR;
                default:
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    return OPENVPN_PLUGIN_FUNC_ERROR;
            }
            case 204:
                /* 204 - no second factor, already okay */
                break;
            case 303:
                /* 303 → registration endpoint - in-band registration required */
                if(register_first)
                {
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    *error = "Stuck in a registration loop";
                    return OPENVPN_PLUGIN_FUNC_ERROR;
                }
                else
                {
                    free(chunk.memory);
                    curl_easy_cleanup(curl);
                    return do_auth_request(devs, username, password, txid, origin, error, 1);
                }
            default:
                free(chunk.memory);
                curl_easy_cleanup(curl);
                *error = "Bad result from libcurl fetching response";
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }
    }
    
    sprintf(url, "https://%s/auth/%s", origin, txid);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    
    // Call curl_easy_setopt()?
    CURLcode curl_result=curl_easy_perform(curl);
    if(curl_result!=CURLE_OK)
    {
        free(chunk.memory);
        curl_easy_cleanup(curl);
        *error = "Error from libcurl";
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_result);
    switch(http_result)
    {
        case 200:
            /* 200, body: (JSON blob) - challenge being provided */
            // Convert to null-terminated string
            auth_challenge=malloc(chunk.size+1);
            memcpy(auth_challenge, chunk.memory, chunk.size);
            memset(auth_challenge, 0, chunk.size);
            
            char response[2048];
            size_t response_len = sizeof (response);
            
            u2fh_rc result = u2fh_authenticate2(devs, auth_challenge, origin,
                                                response, &response_len,
                                                U2FH_REQUEST_USER_PRESENCE);
            free(auth_challenge);
            
            if(result != U2FH_OK)
            {
                curl_easy_cleanup(curl);
                return OPENVPN_PLUGIN_FUNC_ERROR;
            }
            
            // Convert to null-terminated string
            memset(response, 0, response_len);
            
            sprintf(url, "https://%s/auth/%s", origin, txid);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_POST, 1);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, response);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, response_len);
            
            curl_result=curl_easy_perform(curl);
            if(curl_result!=CURLE_OK)
            {
                free(chunk.memory);
                curl_easy_cleanup(curl);
                *error = "Error from libcurl";
                return OPENVPN_PLUGIN_FUNC_ERROR;
            }
            
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_result);
            switch(http_result)
        {
            case 202:
                /* 202 - OK */
                free(chunk.memory);
                curl_easy_cleanup(curl);
                return OPENVPN_PLUGIN_FUNC_SUCCESS;
            case 403:
                /* 403 - bad response */
                free(chunk.memory);
                curl_easy_cleanup(curl);
                return OPENVPN_PLUGIN_FUNC_ERROR;
            default:
                free(chunk.memory);
                curl_easy_cleanup(curl);
                return OPENVPN_PLUGIN_FUNC_ERROR;
        }
        case 204:
            /* 204 - no second factor, already okay */
            free(chunk.memory);
            curl_easy_cleanup(curl);
            return OPENVPN_PLUGIN_FUNC_SUCCESS;
            break;
        case 303:
            /* 303 → registration endpoint - in-band registration required */
            free(chunk.memory);
            curl_easy_cleanup(curl);
            return do_auth_request(devs, username, password, txid, origin, error, 1);
            break;
        default:
            free(chunk.memory);
            curl_easy_cleanup(curl);
            *error = "Bad result from libcurl fetching response";
            return OPENVPN_PLUGIN_FUNC_ERROR;
    }
}

OPENVPN_EXPORT int openvpn_plugin_open_v3(int version, struct openvpn_plugin_args_open_in const *args, struct openvpn_plugin_args_open_return *ret)
{
    struct u2f_client_context *ctx = calloc(1, sizeof(struct u2f_client_context));
    if (!ctx)
    {
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    ctx->global_vtab = args->callbacks;

    ret->type_mask = OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY);
    ret->handle = (openvpn_plugin_handle_t *)ctx;
    return OPENVPN_PLUGIN_FUNC_SUCCESS;
}

OPENVPN_EXPORT int openvpn_plugin_func_v1(openvpn_plugin_handle_t handle, int type, const char *argv[], const char *envp[])
{
    struct u2f_client_context *ctx =
        (struct u2f_client_context *)handle;
    if (type != OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY)
        return OPENVPN_PLUGIN_FUNC_ERROR;

    const char *username = get_env("username", envp);
    const char *password = get_env("password", envp);
    const char *txid = get_env("sessionid", envp);
    const char *origin = get_env("origin", envp);
    const char *acf = get_env("auth_control_file", envp);
    const char *error=NULL;

    /* Note that in optional mode these could be empty strings, not just NULL. */
    if (!username || !password || !origin)
    {
        u2f_client_log(ctx, PLOG_ERR,
                       "expected username, password, and origin in environment set");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    if (!acf)
    {
        u2f_client_log(ctx, PLOG_ERR,
                       "can't do deferred auth with no auth_control_file!");
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }

    int acf_fd = open(acf, O_WRONLY, 0600);
    if (acf_fd == -1)
    {
        u2f_client_log(ctx, PLOG_ERR | PLOG_ERRNO,
                       "open auth_control_file %s", acf);
        return OPENVPN_PLUGIN_FUNC_ERROR;
    }
    
    u2fh_initflags flags=U2FH_DEBUG;
    u2fh_rc result = u2fh_global_init(flags);
    if(result != U2FH_OK)
    {
        fprintf(stderr, "Error initializing u2fh library: %s", u2fh_strerror(result));
        u2fh_global_done();
        exit(67);
    }
    
    u2fh_devs *devs;
    result = u2fh_devs_init(&devs);
    if(result != U2FH_OK)
    {
        fprintf(stderr, "Error initializing u2fh device list: %s", u2fh_strerror(result));
        u2fh_global_done();
        exit(68);
    }
    
    result = u2fh_devs_discover(devs, NULL);
    if(result != U2FH_OK)
    {
        fprintf(stderr, "No U2F devices found: %s", u2fh_strerror(result));
        u2fh_devs_done(devs);
        u2fh_global_done();
        exit(69);
    }
    
    result = do_auth_request(devs, username, password, txid, origin, &error, 0);
    
    u2fh_devs_done(devs);
    
    return result;
}

OPENVPN_EXPORT void openvpn_plugin_close_v1(openvpn_plugin_handle_t handle)
{
    struct u2f_client_context *ctx = (struct u2f_client_context *)handle;
    free(ctx);
    
    u2fh_global_done();
}

OPENVPN_EXPORT void openvpn_plugin_abort_v1(openvpn_plugin_handle_t handle)
{
    /* TODO: should this just be the same as above? */
    struct u2f_client_context *ctx = (struct u2f_client_context *)handle;

    free(ctx);
}
