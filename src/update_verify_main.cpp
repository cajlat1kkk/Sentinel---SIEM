#include "fleet/common.h"
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QTextStream>
#include <QVersionNumber>
#ifdef Q_OS_WIN
#include <windows.h>

#include <bcrypt.h>
#include <wincrypt.h>
#else
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#endif
using namespace siem::fleet;
static bool verify(const QByteArray &key, const QByteArray &message, const QByteArray &signature) {
#ifdef Q_OS_WIN
    DWORD size = 0;
    if (!CryptStringToBinaryA(key.constData(), DWORD(key.size()), CRYPT_STRING_BASE64HEADER, nullptr, &size,
                              nullptr, nullptr))
        return false;
    QByteArray der(int(size), '\0');
    if (!CryptStringToBinaryA(key.constData(), DWORD(key.size()), CRYPT_STRING_BASE64HEADER,
                              reinterpret_cast<BYTE *>(der.data()), &size, nullptr, nullptr))
        return false;
    CERT_PUBLIC_KEY_INFO *info = nullptr;
    DWORD infoSize = 0;
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
                             reinterpret_cast<const BYTE *>(der.constData()), size, CRYPT_DECODE_ALLOC_FLAG,
                             nullptr, &info, &infoSize))
        return false;
    BCRYPT_KEY_HANDLE handle = nullptr;
    const bool imported = CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, info, 0, nullptr, &handle);
    LocalFree(info);
    require(imported, QString("Windows public-key import failed: %1").arg(GetLastError()));
    ULONG bits = 0, got = 0;
    const auto hash = QCryptographicHash::hash(message, QCryptographicHash::Sha256);
    BCRYPT_PKCS1_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM};
    // KeyLength applies to symmetric providers; KeyStrength is the RSA key bit count.
    const auto propertyStatus = BCryptGetProperty(handle, BCRYPT_KEY_STRENGTH,
                                                  reinterpret_cast<PUCHAR>(&bits), sizeof(bits), &got, 0);
    if (propertyStatus != 0 || bits < 2048) {
        BCryptDestroyKey(handle);
        require(false, QString("Windows RSA key length rejected: status %1, bits %2")
                           .arg(quint32(propertyStatus), 0, 16)
                           .arg(bits));
    }
    const auto signatureStatus = BCryptVerifySignature(
        handle, &padding, reinterpret_cast<PUCHAR>(const_cast<char *>(hash.constData())), ULONG(hash.size()),
        reinterpret_cast<PUCHAR>(const_cast<char *>(signature.constData())), ULONG(signature.size()),
        BCRYPT_PAD_PKCS1);
    BCryptDestroyKey(handle);
    require(signatureStatus == 0,
            QString("Windows signature verification failed: %1").arg(quint32(signatureStatus), 0, 16));
    return true;
#else
    auto *bio = BIO_new_mem_buf(key.constData(), int(key.size()));
    if (!bio)
        return false;
    auto *pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pkey)
        return false;
    auto *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *keyContext = nullptr;
    bool ok = ctx && EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA && EVP_PKEY_bits(pkey) >= 2048 &&
              EVP_DigestVerifyInit(ctx, &keyContext, EVP_sha256(), nullptr, pkey) == 1 &&
              EVP_PKEY_CTX_set_rsa_padding(keyContext, RSA_PKCS1_PADDING) == 1 &&
              EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char *>(signature.constData()),
                               size_t(signature.size()),
                               reinterpret_cast<const unsigned char *>(message.constData()),
                               size_t(message.size())) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
#endif
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    app.setApplicationName("siem-update-verify");
    app.setApplicationVersion("0.3.0");
    QCommandLineParser p;
    p.addHelpOption();
    p.addVersionOption();
    p.addOption({"manifest", "Signed release manifest", "file"});
    p.addOption({"signature", "Detached RSA/SHA-256 signature", "file"});
    p.addOption({"public-key", "Locally pinned release public key (not supplied by the downloaded manifest)",
                 "file"});
    p.addOption({"package", "Downloaded package in a protected staging directory", "file"});
    p.addOption({"report", "Write a machine-readable verification result", "file"});
    p.addOption(
        {"minimum-sequence", "Last installed release sequence; reject replay/downgrade", "number", "0"});
    p.process(app);
    try {
        auto bytes = readFile(p.value("manifest"), 65536);
        require(verify(readFile(p.value("public-key"), 16384), bytes, readFile(p.value("signature"), 1024)),
                "Release signature invalid");
        const auto doc = QJsonDocument::fromJson(bytes);
        require(doc.isObject(), "Invalid release manifest");
        auto m = doc.object();
        for (auto it = m.begin(); it != m.end(); ++it)
            require(QStringList{"version", "sequence", "platform", "sha256", "size", "package", "expires"}
                        .contains(it.key()),
                    "Unknown manifest field");
        bool sequenceOk = false;
        auto minimum = p.value("minimum-sequence").toLongLong(&sequenceOk);
        const auto sequence = m["sequence"].toDouble();
        require(sequenceOk && minimum >= 0 && sequence > minimum && sequence <= 9007199254740991.0 &&
                    sequence == double(qint64(sequence)),
                "Release sequence is stale or invalid");
        require(!QVersionNumber::fromString(m["version"].toString()).isNull(), "Invalid release version");
        const auto expiry = QDateTime::fromString(m["expires"].toString(), Qt::ISODate);
        require(expiry.isValid() && expiry > QDateTime::currentDateTimeUtc(), "Release manifest expired");
#ifdef Q_OS_WIN
        require(m["platform"].toString() == "windows-x64", "Package platform mismatch");
#else
        require(m["platform"].toString() == "linux-x64", "Package platform mismatch");
#endif
        QFile file(p.value("package"));
        const auto name = QFileInfo(file).fileName();
        require(name == m["package"].toString() && !name.contains('/') && !name.contains('\\'),
                "Package filename mismatch");
        require(file.open(QIODevice::ReadOnly), "Cannot read package");
        require(file.size() > 0 && double(file.size()) == m["size"].toDouble(), "Package size mismatch");
        QCryptographicHash hash(QCryptographicHash::Sha256);
        require(hash.addData(&file), "Package read error");
        require(QString::fromLatin1(hash.result().toHex()) == m["sha256"].toString(),
                "Package SHA-256 mismatch");
        QTextStream(stdout) << "Verified release " << m["version"].toString() << ", sequence "
                            << qint64(sequence) << '\n';
        if (p.isSet("report"))
            writePrivate(p.value("report"), QJsonDocument(QJsonObject{{"ok", true},
                                                                      {"version", m["version"]},
                                                                      {"sequence", m["sequence"]}})
                                                .toJson());
        return 0;
    } catch (const std::exception &e) {
        QTextStream(stderr) << e.what() << '\n';
        if (p.isSet("report")) {
            try {
                writePrivate(p.value("report"),
                             QJsonDocument(QJsonObject{{"ok", false}, {"error", QString::fromUtf8(e.what())}})
                                 .toJson());
            } catch (...) {
            }
        }
        return 1;
    }
}
