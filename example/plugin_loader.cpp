#include <QCoreApplication>
#include <QCommandLineParser>
#include <QPluginLoader>
#include <QDebug>
#include <QObject>
#include <QtPlugin>
#include <QString>
#include <QMetaMethod>
#include <QMetaProperty>
#include <QMetaEnum>

// Minimal local declaration of the PluginInterface with the same IID
class PluginInterface
{
public:
    virtual ~PluginInterface() {}
    virtual QString name() const = 0;
    virtual QString version() const = 0;
};

#define PluginInterface_iid "com.example.PluginInterface"
Q_DECLARE_INTERFACE(PluginInterface, PluginInterface_iid)

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setApplicationName("plugin_loader");
    app.setApplicationVersion("1.0");

    QCommandLineParser parser;
    parser.setApplicationDescription("Minimal Qt plugin loader example");
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption pluginPathOption(QStringList() << "p" << "path",
                                       "Path to the plugin file (.so/.dylib)",
                                       "plugin_path");
    parser.addOption(pluginPathOption);

    parser.process(app);

    QString pluginPath = parser.value(pluginPathOption);
    if (pluginPath.isEmpty()) {
        qCritical() << "Plugin path must be specified with --path";
        return 1;
    }

    qInfo() << "Loading plugin from" << pluginPath;

    QPluginLoader loader(pluginPath);
    QObject *plugin = loader.instance();

    if (!plugin) {
        qCritical() << "Failed to load plugin:" << loader.errorString();
        return 1;
    }

    qInfo() << "Plugin loaded successfully.";

    if (PluginInterface *iface = qobject_cast<PluginInterface *>(plugin)) {
        qInfo() << "Plugin name:" << iface->name();
        qInfo() << "Plugin version:" << iface->version();
    } else {
        const QMetaObject *meta = plugin->metaObject();
        if (meta) {
            qInfo() << "Qt class name:" << meta->className();
        }
    }

    // List all available methods
    qInfo() << "\n=== Available Methods ===";
    const QMetaObject *metaObject = plugin->metaObject();
    if (metaObject) {
        qInfo() << "Class:" << metaObject->className();
        
        // List all methods (signals, slots, and invokable methods)
        for (int i = 0; i < metaObject->methodCount(); ++i) {
            QMetaMethod method = metaObject->method(i);
            QString methodType;
            
            switch (method.methodType()) {
                case QMetaMethod::Method:
                    methodType = "Method";
                    break;
                case QMetaMethod::Signal:
                    methodType = "Signal";
                    break;
                case QMetaMethod::Slot:
                    methodType = "Slot";
                    break;
                case QMetaMethod::Constructor:
                    methodType = "Constructor";
                    break;
                default:
                    methodType = "Unknown";
                    break;
            }
            
            QString signature = method.methodSignature();
            QString returnType = method.typeName();
            
            qInfo() << QString("  [%1] %2 -> %3").arg(methodType, 10).arg(signature).arg(returnType);
        }
        
        // List all properties
        qInfo() << "\n=== Available Properties ===";
        for (int i = 0; i < metaObject->propertyCount(); ++i) {
            QMetaProperty property = metaObject->property(i);
            QString propertyInfo = QString("  %1 (%2)").arg(property.name()).arg(property.typeName());
            if (property.isReadable()) propertyInfo += " [readable]";
            if (property.isWritable()) propertyInfo += " [writable]";
            qInfo() << propertyInfo;
        }
        
        // List all enums
        qInfo() << "\n=== Available Enums ===";
        for (int i = 0; i < metaObject->enumeratorCount(); ++i) {
            QMetaEnum enumerator = metaObject->enumerator(i);
            qInfo() << QString("  %1:").arg(enumerator.name());
            for (int j = 0; j < enumerator.keyCount(); ++j) {
                qInfo() << QString("    %1 = %2").arg(enumerator.key(j)).arg(enumerator.value(j));
            }
        }
    } else {
        qWarning() << "No meta-object available for plugin";
    }

    return 0;
}


