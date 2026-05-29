// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <falcosecurity/sdk.h>
#include "../../src/include/gsreldata.h"
#include "../falco_shim.h"


#define PLUGIN_ID 9999
#define PLUGIN_NAME "secpoline"
#define PLUGIN_DESCRIPTION "secpoline syscall interception"
#define PLUGIN_CONTACT ""
#define PLUGIN_VERSION "0.1.0"
#define PLUGIN_SOURCE_NAME "secpoline"

#define PLUGIN_LOG_PREFIX "[secpoline]"
#define DEFAULT_JITTER 10
#define DEFAULT_MAX_EVENTS 20
#define DEFAULT_START_VALUE 1

class secpoline_source
{
    public:
    virtual ~secpoline_source() = default;

    secpoline_source(ThreadSafeQueue* intput_q):
     m_enc()
    {
        q = intput_q;
    }

    falcosecurity::result_code next_event(falcosecurity::event_writer &evt)
    {
        if(q == NULL) return falcosecurity::result_code::SS_PLUGIN_FAILURE;
        syscall_t* event;
        int ret = -1;
        while(ret == -1){
            ret = q->pop(&event);
        }
        m_enc.set_data((void *)event, sizeof(syscall_t));
        m_enc.encode(evt);
        free(event);
        return falcosecurity::result_code::SS_PLUGIN_SUCCESS;
    }

    private:
    
    ThreadSafeQueue* q = NULL;
    falcosecurity::events::pluginevent_e_encoder m_enc;
};

class secpoline
{
    public:
    virtual ~secpoline() = default;

    std::string get_name() { return PLUGIN_NAME; }

    std::string get_version() { return PLUGIN_VERSION; }

    std::string get_description() { return PLUGIN_DESCRIPTION; }

    std::string get_contact() { return PLUGIN_CONTACT; }

    uint32_t get_id() { return PLUGIN_ID; };

    std::string get_event_source() { return PLUGIN_SOURCE_NAME; }

    std::string get_last_error() { return m_lasterr; }

    bool init(falcosecurity::init_input &in)
    {
        printf("init secpoline\n");
        return true;
    }

    std::vector<std::string> get_extract_event_sources()
    {
        return {PLUGIN_SOURCE_NAME};
    }

    std::vector<falcosecurity::field_info> get_fields()
    {
        // We need to compile at least with c++11 to use an ordinary initializer
        // list.
        auto secpoline_arg = falcosecurity::field_arg();
        secpoline_arg.required = true;
        secpoline_arg.index = true;

        using ft = falcosecurity::field_value_type;
        return {
                {ft::FTYPE_UINT64, "secpoline.syscall_num",
                 "system call number",
                 "system call number"},
                {ft::FTYPE_UINT64, "secpoline.arg1",
                 "Arg1",
                 "Arg1"},
                {ft::FTYPE_UINT64, "secpoline.arg2",
                 "Arg2",
                 "Arg2"},
                {ft::FTYPE_UINT64, "secpoline.arg3",
                 "Arg3",
                 "Arg3"},
                {ft::FTYPE_UINT64, "secpoline.arg4",
                 "Arg4",
                 "Arg4"},
                {ft::FTYPE_UINT64, "secpoline.arg5",
                 "Arg5",
                 "Arg5"},
                {ft::FTYPE_UINT64, "secpoline.arg6",
                 "Arg6",
                 "Arg6"},
        };
    }

    void log_error(std::string err_mess)
    {
        printf("%s %s\n", PLUGIN_LOG_PREFIX, err_mess.c_str());
    }

    bool extract(const falcosecurity::extract_fields_input &in)
    {
        auto &req = in.get_extract_request();
        falcosecurity::events::pluginevent_e_decoder dec(in.get_event_reader());
        uint32_t len = 0;
        syscall_t* sample = (syscall_t *)(dec.get_data(len));
        switch(req.get_field_id())
        {
        case 0:
        {
            req.set_value((size_t)sample->syscall_num, true);
            return true;
        }
        case 1:
        {
            req.set_value((size_t)sample->arg1, true);
            return true;
        }
        case 2:
        {
            req.set_value((size_t)sample->arg2, true);
            return true;
        }
        case 3:
        {
            req.set_value((size_t)sample->arg3, true);
            return true;
        }
        case 4:
        {
            req.set_value((size_t)sample->arg4, true);
            return true;
        }
        case 5:
        {
            req.set_value((size_t)sample->arg5, true);
            return true;
        }
        case 6:
        {
            req.set_value((size_t)sample->arg6, true);
            return true;
        }
        default:
            m_lasterr = "no known field: " + std::to_string(req.get_field_id());
            log_error(m_lasterr);
            return false;
        }

        return false;
    }

    std::unique_ptr<secpoline_source> open(const std::string &params)
    {
        GSRelativeData* gs = (GSRelativeData* )read_gs_base();
        assert(gs != NULL);
        q = (ThreadSafeQueue*)gs->plugin_queue;
        q->activate();


        return std::unique_ptr<secpoline_source>(new secpoline_source(q));
    }

    ThreadSafeQueue* q = NULL;
    std::string m_lasterr = "";
    uint64_t m_jitter = DEFAULT_JITTER;
};

FALCOSECURITY_PLUGIN(secpoline);
FALCOSECURITY_PLUGIN_EVENT_SOURCING(secpoline, secpoline_source);
FALCOSECURITY_PLUGIN_FIELD_EXTRACTION(secpoline);
