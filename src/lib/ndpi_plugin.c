/*
 * ndpi_plugin.c
 *
 * Copyright (C) 2011-25 - ntop.org and contributors
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <sys/types.h>

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "ndpi_includes.h"
#include "ndpi_private.h"

#if !(defined(WIN32) || defined(WIN64))
#include <dlfcn.h>
#include <dirent.h>
#endif

#define NDPI_PLUGIN_DEBUG

/* ************************************** */

/* Load a single protocol plugin */
#if !(defined(WIN32) || defined(WIN64))
static bool ndpi_load_protocol_plugin(struct ndpi_detection_module_struct *ndpi_struct,
				      char *plugin_path) {
  void *pluginEntryFctnPtr;
  NDPIProtocolPluginEntryPoint* (*pluginEntryFctn)(void);
  void *pluginPtr;
  NDPIProtocolPluginEntryPoint *pluginInfo;

  if(ndpi_struct->proto_plugins.num_loaded_plugins == (NDPI_MAX_NUM_PLUGINS-1)) {
#ifdef NDPI_PLUGIN_DEBUG
    printf("WARNING: too many plugins loadeded %u\n", ndpi_struct->proto_plugins.num_loaded_plugins);
#endif
    return(false);
  }
  
  pluginPtr = (void*)dlopen(plugin_path, RTLD_NOW /* RTLD_LAZY */); /* Load the library */
  
  if(pluginPtr == NULL) {
#ifdef NDPI_PLUGIN_DEBUG
    printf("WARNING: unable to load plugin '%s': %s", plugin_path, dlerror());
#endif
    return(false);
  }

  pluginEntryFctnPtr = (void*)dlsym(pluginPtr, "PluginEntryFctn");
  if(pluginEntryFctnPtr == NULL) {
#ifdef NDPI_PLUGIN_DEBUG
    printf("WARNING: unable to locate plugin entryfunction %s", plugin_path);
#endif
    return(false);
  }

  pluginEntryFctn = (NDPIProtocolPluginEntryPoint*(*)(void))pluginEntryFctnPtr;
  pluginInfo = pluginEntryFctn();

#ifdef NDPI_PLUGIN_DEBUG
  printf("Loaded plugin %s [v.%s][%s][%s]\n",
	 pluginInfo->protocol_name,
	 pluginInfo->version,
	 pluginInfo->author,
	 plugin_path);
#endif
  

  /* Execute init function */
  pluginInfo->initFctn(ndpi_struct);
  
  ndpi_struct->proto_plugins.plugin[ndpi_struct->proto_plugins.num_loaded_plugins++] = pluginPtr;
  return(false);
}
#endif

/* ************************************** */

u_int ndpi_load_protocol_plugins(struct ndpi_detection_module_struct *ndpi_struct,
				char *dir_path) {
#if defined(WIN32) || defined(WIN64)
  __ndpi_unused_param(ndpi_struct);
  __ndpi_unused_param(dir_path);
  return(0);
#else
  DIR *dirp;
  struct dirent *dp;
  int failed_files = 0;
  int num_loaded = 0;

  if(!ndpi_struct || !dir_path)
    return(-1);

  dirp = opendir(dir_path);
  if (dirp == NULL)
    return(-1);

  while((dp = readdir(dirp)) != NULL) {
    char *extn, path[512];

    if(dp->d_name[0] == '.') continue;
    extn = strrchr(dp->d_name, '.');

    if((extn == NULL) || strcmp(extn, ".so"))
      continue;

    snprintf(path, sizeof(path), "%s/%s", dir_path, dp->d_name);
    if(ndpi_load_protocol_plugin(ndpi_struct, path))
      num_loaded++;
  } /* while */

  (void)closedir(dirp);

  if(failed_files)
    return(-1 * failed_files);

  return(num_loaded);
#endif
}

/* ************************************** */

void ndpi_unload_protocol_plugins(struct ndpi_detection_module_struct *ndpi_struct) {
#if !(defined(WIN32) || defined(WIN64))
  u_int i;

  for(i=0; i<ndpi_struct->proto_plugins.num_loaded_plugins; i++)
    dlclose(ndpi_struct->proto_plugins.plugin[i]);
#else
  __ndpi_unused_param(ndpi_struct);
#endif
}

/* ************************************** */
