#include "capability_module_impl.h"

#include <QByteArray>
#include <QDebug>
#include <QUuid>

#include <algorithm>

#include "logos_api.h"
#include "logos_api_client.h"
#include "token_manager.h"

namespace {

// Constant-time token comparison (mirrors ModuleProxy's): compare over the
// longer of the two lengths and fold any length difference into the result,
// so neither a correct prefix nor the secret's length leaks through timing.
bool constantTimeEquals(const QString& a, const QString& b)
{
    const QByteArray ba = a.toUtf8();
    const QByteArray bb = b.toUtf8();
    const int n = std::max(ba.size(), bb.size());
    int diff = ba.size() ^ bb.size();
    for (int i = 0; i < n; ++i) {
        const unsigned char ca = i < ba.size() ? static_cast<unsigned char>(ba[i]) : 0;
        const unsigned char cb = i < bb.size() ? static_cast<unsigned char>(bb[i]) : 0;
        diff |= (ca ^ cb);
    }
    return diff == 0;
}

} // namespace

QString CapabilityModuleImpl::requestModule(const QString& fromModuleName, const QString& moduleName)
{
    qDebug() << "CapabilityModuleImpl::requestModule called with fromModuleName:" << fromModuleName
             << "moduleName:" << moduleName;

    LogosAPI* api = logosAPI();
    if (!api) {
        qWarning() << "CapabilityModuleImpl::requestModule: LogosAPI not initialized";
        return {};
    }

    if (fromModuleName.isEmpty() || moduleName.isEmpty()) {
        qWarning() << "CapabilityModuleImpl::requestModule: rejecting empty module name"
                   << "(fromModuleName / moduleName must both be set)";
        return {};
    }

    TokenManager* tokenManager = api->getTokenManager();

    // Known-caller gate: the requesting identity must be a module capability_module
    // already knows about. Fail closed on an unknown name rather than mint a token
    // for a self-asserted identity that was never loaded.
    if (!tokenManager->getTokenKeys().contains(fromModuleName)) {
        qWarning() << "CapabilityModuleImpl::requestModule: rejecting request from unknown"
                   << "module identity:" << fromModuleName
                   << "- no token registered for it (unverified requesting identity)";
        return {};
    }

    // Known-target gate: an empty target token means the target is not loaded /
    // unknown. Don't hand back a token the target would reject anyway — fail closed.
    const QString moduleToken = tokenManager->getToken(moduleName);
    if (moduleToken.isEmpty()) {
        qWarning() << "CapabilityModuleImpl::requestModule: rejecting request for unknown"
                   << "target module:" << moduleName << "- no token registered for it";
        return {};
    }

    // Access-policy gate: if core registered a restriction for this target,
    // only the listed callers may obtain a token. A target with no registered
    // restriction is unrestricted (back-compat). Fail closed for a restricted
    // target — the denied caller never gets a token, so it can never call it.
    if (auto it = m_restrictions.constFind(moduleName); it != m_restrictions.constEnd()) {
        if (!it->contains(fromModuleName)) {
            qWarning() << "CapabilityModuleImpl::requestModule: access policy denies"
                       << fromModuleName << "->" << moduleName
                       << "- caller not in the allowed set";
            return {};
        }
    }

    const QString authTokenString = QUuid::createUuid().toString(QUuid::WithoutBraces);

    qDebug() << "CapabilityModuleImpl: Calling informModuleToken on target module:" << moduleName;

    const bool success = api->getClient(moduleName)->informModuleToken_module(
        moduleToken, moduleName, fromModuleName, authTokenString);
    if (!success) {
        qWarning() << "CapabilityModuleImpl: Failed to inform" << moduleName
                   << "about token for" << fromModuleName;
        return {};
    }

    qDebug() << "CapabilityModuleImpl: Successfully informed" << moduleName
             << "about token for" << fromModuleName;
    return authTokenString;
}

bool CapabilityModuleImpl::registerRestriction(const QString& authToken,
                                               const QString& targetModule,
                                               const QStringList& allowedCallers)
{
    LogosAPI* api = logosAPI();
    if (!api) {
        qWarning() << "CapabilityModuleImpl::registerRestriction: LogosAPI not initialized";
        return false;
    }

    // Trusted-channel gate: only core (or capability_module itself) may
    // register restrictions. Both hold capability_module's auth token; a
    // peer module only knows its own token and so cannot forge this. Same
    // check ModuleProxy::informModuleToken makes — necessary because the
    // generic isAuthorized() that fronts this method accepts ANY issued
    // token, which would otherwise let a malicious module rewrite the policy.
    TokenManager* tokenManager = api->getTokenManager();
    const QString coreToken = tokenManager->getToken(QStringLiteral("core"));
    const QString capToken  = tokenManager->getToken(QStringLiteral("capability_module"));
    const bool callerIsTrusted =
        (!coreToken.isEmpty() && constantTimeEquals(authToken, coreToken)) ||
        (!capToken.isEmpty()  && constantTimeEquals(authToken, capToken));
    if (authToken.isEmpty() || !callerIsTrusted) {
        qWarning() << "CapabilityModuleImpl::registerRestriction: rejecting restriction for"
                   << targetModule << "- caller is not the trusted core channel";
        return false;
    }

    if (targetModule.isEmpty()) {
        qWarning() << "CapabilityModuleImpl::registerRestriction: rejecting empty target module";
        return false;
    }

    // Overwrite any previous restriction for this target — core is the
    // single source of truth and re-registers the full set each boot.
    m_restrictions.insert(targetModule, QSet<QString>(allowedCallers.begin(), allowedCallers.end()));

    qDebug() << "CapabilityModuleImpl::registerRestriction: target" << targetModule
             << "restricted to callers" << allowedCallers;
    return true;
}
