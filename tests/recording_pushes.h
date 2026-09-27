#pragma once

// Records token pushes and revocations instead of dialling targets; a push can be
// held open so a test can race it.

#include <logos_test.h>
#include <logos_protocol.h>

#include "capability_authority.h"
#include "capability_module_impl.h"
#include "logos_capability_engine.h"

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

extern "C" const logos_capability_engine_v1* logos_module_capability_engine_v1();

namespace recording {

inline const logos_capability_engine_v1& engine()
{
    return *logos_module_capability_engine_v1();
}

inline std::string take(char* value)
{
    std::string text = value ? value : "";
    engine().string_free(value);
    return text;
}

inline std::string digestOf(const std::string& token)
{
    char* digest = lp_token_digest(token.c_str());
    std::string value = digest ? digest : "";
    lp_string_free(digest);
    return value;
}

class Pushes {
public:
    Pushes()
    {
        CapabilityAuthority::instance().setTokenPush([this](const CapabilityAuthority::Push& push) {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_pushes.push_back(push);
            ++m_started;
            m_changed.notify_all();
            m_changed.wait(lock, [this] { return !m_hold; });
            return m_status;
        });
        CapabilityAuthority::instance().setRevocationPush(
            [this](const CapabilityAuthority::Revocation& revocation, const std::string&) {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_revoked.push_back(revocation);
                return LP_OK;
            });
    }
    ~Pushes()
    {
        release();
        for (const auto& [name, generation] : m_admitted) engine().retire(name.c_str(), generation);
        engine().set_restrictions("{}");
        CapabilityAuthority::instance().drainRevocations();
        CapabilityAuthority::instance().setTokenPush({});
        CapabilityAuthority::instance().setRevocationPush({});
    }
    Pushes(const Pushes&) = delete;
    Pushes& operator=(const Pushes&) = delete;

    void admit(const std::string& name)
    {
        unsigned long long generation = 0;
        char* credential = engine().admit(name.c_str(), "module", &generation);
        engine().string_free(credential);
        m_admitted.emplace_back(name, generation);
    }
    void retire(const std::string& name)
    {
        for (auto it = m_admitted.begin(); it != m_admitted.end(); ++it) {
            if (it->first != name) continue;
            engine().retire(name.c_str(), it->second);
            m_admitted.erase(it);
            return;
        }
    }

    void answer(int status)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_status = status;
    }
    void hold()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hold = true;
    }
    void release()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_hold = false;
        m_changed.notify_all();
    }
    // Waits until `count` pushes have started.
    bool started(int count)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        return m_changed.wait_for(lock, std::chrono::seconds(5), [&] { return m_started >= count; });
    }
    std::vector<CapabilityAuthority::Push> pushes()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pushes;
    }
    std::vector<CapabilityAuthority::Revocation> revoked()
    {
        CapabilityAuthority::instance().drainRevocations();
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_revoked;
    }

private:
    std::mutex m_mutex;
    std::condition_variable m_changed;
    std::vector<CapabilityAuthority::Push> m_pushes;
    std::vector<CapabilityAuthority::Revocation> m_revoked;
    std::vector<std::pair<std::string, unsigned long long>> m_admitted;
    int m_status = LP_OK;
    int m_started = 0;
    bool m_hold = false;
};

// requestModule as `caller`, on this thread.
inline std::string request(const char* caller, const char* target)
{
    CapabilityModuleImpl impl;
    const auto as = logos::CallCaller::module(caller);
    return impl.requestModule("", target);
}

} // namespace recording
