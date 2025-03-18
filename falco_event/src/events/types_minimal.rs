use falco_event_derive::event_info;

event_info! {
        [PPME_PLUGINEVENT_E] = {"pluginevent",
                                EC_OTHER | EC_PLUGIN,
                                EF_LARGE_PAYLOAD,
                                2,
                                {{"plugin_id", PT_UINT32, PF_DEC},
                                 {"event_data", PT_BYTEBUF, PF_NA}}},
        [PPME_ASYNCEVENT_E] = {"asyncevent",
                               EC_OTHER | EC_METAEVENT,
                               EF_LARGE_PAYLOAD,
                               3,
                               {{"plugin_id", PT_UINT32, PF_DEC},
                                {"name", PT_CHARBUF, PF_NA},
                                {"data", PT_BYTEBUF, PF_NA}}},
}
