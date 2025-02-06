
# Library Initialization

A simple, common example

```

struct ndpi_detection_module_struct *ndpi_struct;
ndpi_cfg_error rc;
int ret;

ndpi_struct = ndpi_init_detection_module(NULL);
if(!ndpi_struct) {
	ERROR;
}

/* Configuration */

rc = ndpi_set_config(ndpi_struct, "tls", "certificate_expiration_threshold", "10");
if(rc != NDPI_CFG_OK) {
	ERROR;
}

/* Finalization */
ret = ndpi_finalize_initialization(ndpi_struct);
if(ret != 0) {
	ERROR;
}


/* Initialization done, now you can feed packets to the library */



/* Cleanup */

ndpi_exit_detection_module(ndpi_struct);


```

A more complex example, with global context and a shared Oookla LRU cache (all the others caches are local)

```

struct ndpi_global_context *g_ctx;
struct ndpi_detection_module_struct *ndpi_structs[num_local_contexts];
ndpi_cfg_error rc;
int i, ret;

g_ctx = ndpi_global_init();
if(!g_ctx) {
	ERROR;
}

for(i = 0; i < num_local_contexts; i++) {
	ndpi_structs[i] = ndpi_init_detection_module(g_ctx);
	if(!ndpi_struct[i]) {
		ERROR;
	}

	rc = ndpi_set_config(ndpi_structs[i], NULL, "lru.ookla.scope", "1");
	if(rc != NDPI_CFG_OK) {
		ERROR;
	}

	ret = ndpi_finalize_initialization(ndpi_structs[i]);
	if(ret != 0) {
		ERROR;
	}
}

/* Initialization done */

/* Cleanup */

for(i = 0; i < num_local_contexts; i++) {
	ndpi_exit_detection_module(ndpi_structs[i]);
}

ndpi_global_deinit(g_ctx);


```
