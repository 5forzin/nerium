#pragma once

int install_uname_listener(bool proc_enabled, bool platform_supervisor);
void serve_uname_listener(int listener, int client);
