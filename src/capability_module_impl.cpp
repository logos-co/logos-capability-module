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

    TokenManager* tokenManager = api->getTokenManager();
    for (const QString& key : tokenManager->getTokenKeys()) {
        qDebug() << "CapabilityModuleImpl::requestModule token key:" << key
                 << "value:" << tokenManager->getToken(key);
    }

    const QString authTokenString = QUuid::createUuid().toString(QUuid::WithoutBraces);
    const QString moduleToken = tokenManager->getToken(moduleName);

    qDebug() << "CapabilityModuleImpl: Calling informModuleToken on target module:" << moduleName;

    // Liveness guard. The fromModuleName process may have died between
    // the caller asking us to issue a token and us reaching this line
    // (observed when a ui-host child SIGTERM'd mid-handshake and the
    // ensuing outbound RPC tripped a Qt-Remote-Objects source-codec
    // race that crashed this whole logos_host with SIGBUS). A
    // synchronous outbound on a torn-down socket is the riskiest
    // moment in that race; refusing it shrinks the window.
    //
    // Returning an empty token instead of bailing earlier preserves
    // the existing contract: the caller already has to handle an
    // empty-token response (basecamp's UIPluginManager treats it as
    // a transient failure and retries). It's a strictly better
    // outcome than crashing the daemon.
    LogosAPIClient* client = api->getClient(moduleName);
    if (!client || !client->isConnected()) {
        qWarning() << "CapabilityModuleImpl: target module" << moduleName
                   << "is not connected; declining to inform token for" << fromModuleName;
        return {};
    }

    const bool success = client->informModuleToken_module(
        moduleToken, moduleName, fromModuleName, authTokenString);
    if (success) {
        qDebug() << "CapabilityModuleImpl: Successfully informed" << moduleName
                 << "about token for" << fromModuleName;
    } else {
        qWarning() << "CapabilityModuleImpl: Failed to inform" << moduleName
                   << "about token for" << fromModuleName;
    }

    qDebug() << "CapabilityModuleImpl::requestModule returning new auth token:" << authTokenString;
    return authTokenString;
}
