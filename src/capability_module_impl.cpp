#include "capability_module_impl.h"

#include <QDebug>
#include <QUuid>

#include "logos_api.h"
#include "logos_api_client.h"
#include "token_manager.h"

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
