// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#ifndef QABSTRACTOAUTH2_H
#define QABSTRACTOAUTH2_H

#ifndef QT_NO_HTTP

#include <QtCore/qdatetime.h>

#include <QtNetworkAuth/qoauthglobal.h>
#include <QtNetworkAuth/qabstractoauth.h>

QT_BEGIN_NAMESPACE

class QSslConfiguration;
class QHttpMultiPart;
class QAbstractOAuth2Private;
class Q_OAUTH_EXPORT QAbstractOAuth2 : public QAbstractOAuth
{
    Q_OBJECT
#if QT_DEPRECATED_SINCE(6, 11)
    Q_PROPERTY(QString scope READ scope WRITE setScope NOTIFY scopeChanged)
#endif
    Q_PROPERTY(QStringList grantedScope READ grantedScope NOTIFY grantedScopeChanged)
    Q_PROPERTY(QStringList requestedScope
                READ requestedScope
                WRITE setRequestedScope
                NOTIFY requestedScopeChanged)
    Q_PROPERTY(QString userAgent READ userAgent WRITE setUserAgent NOTIFY userAgentChanged)
    Q_PROPERTY(QString clientIdentifierSharedKey
               READ clientIdentifierSharedKey
               WRITE setClientIdentifierSharedKey
               NOTIFY clientIdentifierSharedKeyChanged)
    Q_PROPERTY(QString state READ state WRITE setState NOTIFY stateChanged)
    Q_PROPERTY(QDateTime expiration READ expirationAt NOTIFY expirationAtChanged)
    Q_PROPERTY(QString refreshToken
               READ refreshToken
               WRITE setRefreshToken
               NOTIFY refreshTokenChanged)
    Q_PROPERTY(NonceMode nonceMode READ nonceMode WRITE setNonceMode NOTIFY nonceModeChanged)
    Q_PROPERTY(QString nonce READ nonce WRITE setNonce NOTIFY nonceChanged)
    Q_PROPERTY(QString idToken READ idToken NOTIFY idTokenChanged)

    using TokenRequestModifierPrototype = void(*)(QNetworkRequest&, QAbstractOAuth::Stage);
    template <typename Functor>
    using ContextTypeForFunctor = typename QtPrivate::ContextTypeForFunctor<Functor>::ContextType;
    template <typename Functor>
    using if_compatible_callback = std::enable_if_t<
        QtPrivate::AreFunctionsCompatible<TokenRequestModifierPrototype, Functor>::value, bool>;

public:
    enum class NonceMode : quint8 {
        Automatic,
        Enabled,
        Disabled,
    };
    Q_ENUM(NonceMode)

    explicit QAbstractOAuth2(QObject *parent = nullptr);
    explicit QAbstractOAuth2(QNetworkAccessManager *manager, QObject *parent = nullptr);
    ~QAbstractOAuth2();

    Q_INVOKABLE virtual QUrl createAuthenticatedUrl(const QUrl &url,
                                                    const QVariantMap &parameters = QVariantMap());

    QT_DEPRECATED_VERSION_X_6_11("Use QtNetwork classes instead."
                                 "See https://doc.qt.io/qt-6/oauth-http-method-alternatives.html")
    Q_INVOKABLE QNetworkReply *head(const QUrl &url,
                                    const QVariantMap &parameters = QVariantMap()) override;

    QT_DEPRECATED_VERSION_X_6_11("Use QtNetwork classes instead."
                                 "See https://doc.qt.io/qt-6/oauth-http-method-alternatives.html")
    Q_INVOKABLE QNetworkReply *get(const QUrl &url,
                                   const QVariantMap &parameters = QVariantMap()) override;

    QT_DEPRECATED_VERSION_X_6_11("Use QtNetwork classes instead."
                                 "See https://doc.qt.io/qt-6/oauth-http-method-alternatives.html")
    Q_INVOKABLE QNetworkReply *post(const QUrl &url,
                                    const QVariantMap &parameters = QVariantMap()) override;

    QT_DEPRECATED_VERSION_X_6_11("Use QtNetwork classes instead."
                                 "See https://doc.qt.io/qt-6/oauth-http-method-alternatives.html")
    Q_INVOKABLE virtual QNetworkReply *post(const QUrl &url, const QByteArray &data);

    QT_DEPRECATED_VERSION_X_6_11("Use QtNetwork classes instead."
                                 "See https://doc.qt.io/qt-6/oauth-http-method-alternatives.html")
    Q_INVOKABLE virtual QNetworkReply *post(const QUrl &url, QHttpMultiPart *multiPart);

    QT_DEPRECATED_VERSION_X_6_11("Use QtNetwork classes instead."
                                 "See https://doc.qt.io/qt-6/oauth-http-method-alternatives.html")
    Q_INVOKABLE QNetworkReply *put(const QUrl &url,
                                   const QVariantMap &parameters = QVariantMap()) override;

    QT_DEPRECATED_VERSION_X_6_11("Use QtNetwork classes instead."
                                 "See https://doc.qt.io/qt-6/oauth-http-method-alternatives.html")
    Q_INVOKABLE virtual QNetworkReply *put(const QUrl &url, const QByteArray &data);

    QT_DEPRECATED_VERSION_X_6_11("Use QtNetwork classes instead."
                                 "See https://doc.qt.io/qt-6/oauth-http-method-alternatives.html")
    Q_INVOKABLE virtual QNetworkReply *put(const QUrl &url, QHttpMultiPart *multiPart);

    QT_DEPRECATED_VERSION_X_6_11("Use QtNetwork classes instead."
                                 "See https://doc.qt.io/qt-6/oauth-http-method-alternatives.html")
    Q_INVOKABLE QNetworkReply *deleteResource(const QUrl &url,
                                              const QVariantMap &parameters = QVariantMap()) override;
#if QT_DEPRECATED_SINCE(6, 11)
    QT_DEPRECATED_VERSION_X_6_11("Use requestedScope and grantedScope properties instead.")
    QString scope() const;
    QT_DEPRECATED_VERSION_X_6_11("Use requestedScope and grantedScope properties instead.")
    void setScope(const QString &scope);
#endif

    QStringList grantedScope() const;

    QStringList requestedScope() const;
    void setRequestedScope(const QStringList &scope);

    QString userAgent() const;
    void setUserAgent(const QString &userAgent);

    QString responseType() const;

    QString clientIdentifierSharedKey() const;
    void setClientIdentifierSharedKey(const QString &clientIdentifierSharedKey);

    QString state() const;
    void setState(const QString &state);

    QDateTime expirationAt() const;

    QString refreshToken() const;
    void setRefreshToken(const QString &refreshToken);

    NonceMode nonceMode() const;
    void setNonceMode(NonceMode mode);

    QString nonce() const;
    void setNonce(const QString &nonce);

    QString idToken() const;

#ifndef QT_NO_SSL
    QSslConfiguration sslConfiguration() const;
    void setSslConfiguration(const QSslConfiguration &configuration);
#endif

    void prepareRequest(QNetworkRequest *request, const QByteArray &verb,
                        const QByteArray &body = QByteArray()) override;

    template <typename Functor, if_compatible_callback<Functor> = true>
    void setTokenRequestModifier(const ContextTypeForFunctor<Functor> *context,
                                 Functor &&callback) {
        setTokenRequestModifierImpl(
            context,
            QtPrivate::makeCallableObject<TokenRequestModifierPrototype>(
                std::forward<Functor>(callback)));
    }
    void clearTokenRequestModifier();

Q_SIGNALS:
#if QT_DEPRECATED_SINCE(6, 11)
    QT_DEPRECATED_VERSION_X_6_11("Use requestedScope and grantedScope properties instead.")
    void scopeChanged(const QString &scope);
#endif
    void grantedScopeChanged(const QStringList &scope);
    void requestedScopeChanged(const QStringList &scope);
    void userAgentChanged(const QString &userAgent);
    void responseTypeChanged(const QString &responseType);
    void clientIdentifierSharedKeyChanged(const QString &clientIdentifierSharedKey);
    void stateChanged(const QString &state);
    void expirationAtChanged(const QDateTime &expiration);
    void refreshTokenChanged(const QString &refreshToken);
    void nonceModeChanged(NonceMode mode);
    void nonceChanged(const QString &nonce);
    void idTokenChanged(const QString &idToken);
#ifndef QT_NO_SSL
    void sslConfigurationChanged(const QSslConfiguration &configuration);
#endif

#if QT_DEPRECATED_SINCE(6, 13)
    QT_DEPRECATED_VERSION_X_6_13("Use errorOccurred instead.")
    void error(const QString &error, const QString &errorDescription, const QUrl &uri);
#endif
    void errorOccurred(const QString &error, const QString &errorDescription, const QUrl &uri);
    void authorizationCallbackReceived(const QVariantMap &data);

protected:
    explicit QAbstractOAuth2(QAbstractOAuth2Private &, QObject *parent = nullptr);

    void setResponseType(const QString &responseType);

private:
    void setTokenRequestModifierImpl(const QObject* context, QtPrivate::QSlotObjectBase *slot);
    Q_DECLARE_PRIVATE(QAbstractOAuth2)
};

QT_END_NAMESPACE

#endif // QT_NO_HTTP

#endif // QABSTRACTOAUTH2_H
