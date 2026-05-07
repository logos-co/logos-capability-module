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

    const bool success = api->getClient(moduleName)->informModuleToken_module(
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
