#pragma once

#include <wincrypt.h>
#include <memory>
#include <string>
#include <sstream>
#include <vector>

namespace MIME2 {
class CONTENT;
class CONTENTBUILDER;

void BuildZ(CONTENT &c1, CONTENT &c2, CONTENT &co, const char *s);

enum class MIMEERR {
    OK = 0,
    INVALID = 1,
    NOTSIGNED = 2,
    ERRSIGN = 3,
};

inline std::string Char2Base64(const char *Z, size_t s)
{
    DWORD da = 0;
    CryptBinaryToString((const BYTE *)Z, (DWORD)s, CRYPT_STRING_BASE64, 0, &da);
    std::unique_ptr<char> out(new char[da]);
    CryptBinaryToStringA((const BYTE *)Z, (DWORD)s, CRYPT_STRING_BASE64,
                         out.get(), &da);
    return out.get();
}

inline void Base64ToChar(const char *Z, size_t s, std::vector<char> &out)
{
    DWORD dw = 0;
    CryptStringToBinaryA(Z, (DWORD)s, CRYPT_STRING_BASE64, 0, &dw, 0, 0);
    out.resize(dw);
    CryptStringToBinaryA(Z, (DWORD)s, CRYPT_STRING_BASE64, (BYTE *)out.data(),
                         &dw, 0, 0);
}

MIMEERR ParseMultipleContent2(const char *d, size_t sz, const char *del,
                              std::vector<CONTENT> &Result);

inline void Split(const char *m, char del, std::vector<std::string> &result)
{
    if (!m)
        return;
    std::stringstream ss(m);
    while (ss.good()) {
        std::string substr;
        std::getline(ss, substr, del);
        result.push_back(substr);
    }
}

inline std::string &Trim(std::string &s, int j = 0)
{
    while (s.length() && (j == 0 || j == 1)) {
        if (s[s.length() - 1] == ' ' || s[s.length() - 1] == '\r' ||
            s[s.length() - 1] == '\n' || s[s.length() - 1] == '\t')
            s.erase(s.end() - 1);
        else
            break;
    }
    while (s.length() && (j == 0 || j == 2)) {
        if (s[0] == ' ' || s[0] == '\r' || s[0] == '\n' || s[0] == '\t')
            s.erase(s.begin());
        else
            break;
    }
    return s;
}

inline std::vector<char> &Trim(std::vector<char> &s, int j = 0)
{
    while (s.size() && (j == 0 || j == 1)) {
        if (s[s.size() - 1] == ' ' || s[s.size() - 1] == '\r' ||
            s[s.size() - 1] == '\n' || s[s.size() - 1] == '\t')
            s.erase(s.end() - 1);
        else
            break;
    }
    while (s.size() && (j == 0 || j == 2)) {
        if (s[0] == ' ' || s[0] == '\r' || s[0] == '\n' || s[0] == '\t')
            s.erase(s.begin());
        else
            break;
    }
    return s;
}

inline std::vector<char> &TrimOnce(std::vector<char> &s)
{
    if (s.size()) {
        if (strncmp(s.data() + s.size() - 2, "\r\n", 2) == 0) {
            s.erase(s.end() - 1);
            s.erase(s.end() - 1);
        }
        else if (strncmp(s.data() + s.size() - 1, "\n", 1) == 0) {
            s.erase(s.end() - 1);
        }
    }
    return s;
}

inline void Split(const char *m, const char *del,
                  std::vector<std::string> &result)
{
    if (!m || !del)
        return;
    size_t pos = 0;
    std::string token;
    std::string delimiter = del;
    std::string s = m;
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        result.push_back(token);
        s.erase(0, pos + delimiter.length());
    }
    result.push_back(s);
}

inline void BinarySplit(const char *m, size_t sz, const char *del,
                        std::vector<std::vector<char>> &result)
{
    if (!m || !del)
        return;
    size_t pos = 0;
    std::string token;
    std::string delimiter = del;
    std::string s;
    s.assign(m, sz);
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        std::vector<char> res;
        res.resize(token.size());
        memcpy(res.data(), token.data(), token.size());
        result.push_back(res);
        s.erase(0, pos + delimiter.length());
    }

    std::vector<char> res;
    res.resize(s.size());
    memcpy(res.data(), s.data(), s.size());
    result.push_back(res);
}

class HDRSTRING {
    std::vector<std::string> strs;

  public:
    std::vector<std::string> &getstrings() { return strs; }

    std::string Sub(const char *ga) const
    {
        if (!ga)
            return "";
        for (auto &a : strs) {
            const char *f1 = strchr(a.c_str(), '=');
            if (!f1) {
                if (_stricmp(a.c_str(), ga) == 0)
                    return a;
                continue;
            }
            std::vector<char> leftpart(f1 - a.c_str() + 10);
            strncpy_s(leftpart.data(), leftpart.size(), a.c_str(),
                      f1 - a.c_str());
            if (_strnicmp(leftpart.data(), ga, strlen(ga)) == 0) {
                std::string r = f1 + 1;
                if (r.length() && r[0] == '\"')
                    r.erase(r.begin());
                if (r.length() && r[r.length() - 1] == '\"')
                    r.erase(r.end() - 1);
                return r;
            }
        }
        return "";
    }

    MIMEERR Parse(const char *h)
    {
        strs.clear();
        Split(h, ';', strs);

        for (auto &a : strs) {
            Trim(a);
        }
        for (signed long long i = strs.size() - 1; i >= 0; i--) {
            if (strs[(size_t)i].length() == 0)
                strs.erase(strs.begin() + (size_t)i);
        }

        return MIMEERR::OK;
    }

    std::string Serialize() const
    {
        std::string r;
        for (auto &s : strs) {
            if (r.length())
                r += "; ";
            r += s;
        }
        return r;
    }
};

class HEADER {
    std::string left;
    HDRSTRING right;
    bool http = false;

  public:
    bool IsHTTP() const { return http; }
    std::string Left() const { return left; }
    std::string Right() const { return right.Serialize(); }
    std::string Right(const char *sub) const { return right.Sub(sub); }
    HDRSTRING &rights() { return right; }

    std::vector<std::string> httpsplit()
    {
        std::vector<std::string> hd;
        Split(left.c_str(), ' ', hd);
        return hd;
    }

    void operator=(const char *l) { right.Parse(l); }

    MIMEERR Parse(const char *f, bool CanHTTP = false)
    {
        if (!f)
            return MIMEERR::INVALID;
        const char *a = strchr(f, ':');
        if (!a && !CanHTTP)
            return MIMEERR::INVALID;

        const char *a2 = strchr(f, ' ');
        if ((a2 < a) && CanHTTP)
            a = 0;

        if (!a && CanHTTP) {
            left = f;
            http = true;
            return MIMEERR::OK;
        }

        std::vector<char> d;
        d.resize(a - f + 10);
        strncpy_s(d.data(), d.size(), f, a - f);

        left = d.data();
        a++;
        while (*a == ' ')
            a++;
        right.Parse(a);

        return MIMEERR::OK;
    }

    std::string Serialize() const
    {
        if (http)
            return left;
        std::string r;
        r += left;
        r += ": ";
        r += right.Serialize();
        return r;
    }
};

#define SKIP '\202'
#define NOSKIP 'A'

const char hexmap[] = {
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, 10,   11,   12,   13,   14,   15,   SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP, SKIP,
    SKIP, SKIP, SKIP, SKIP};

class CONTENT {
    std::vector<HEADER> headers;
    std::vector<char> data;

  private:
    char *QPDecode(char *input)
    {
        char *s = input;
        char *finalresult =
            (char *)calloc(strlen(input) + sizeof(char), sizeof(char));
        char *result = finalresult;
        while (*s != '\0') // loop through the entire string...
        {
            if (*s == '=') // woops, needs to be decoded...
            {
                for (int i = 0; i < 3; i++) // is s more than 3 chars long...
                {
                    if (s[i] == '\0') {
                        // error in the decoding...
                        return finalresult;
                    }
                }
                char mid[3];
                s++; // move past the "="
                     // let's put the hex part into mid...
                bool ok = true;
                for (int i = 0; i < 2; i++) {
                    if (hexmap[s[i]] == SKIP) {
                        // we have an error, or a linebreak, in the encoding...
                        ok = false;
                        if (s[i] == '\r' && s[i + 1] == '\n') {
                            s += 2;
                            //*(result++) = '\r';
                            //*(result++) = '\n';
                            break;
                        }
                        else {
                            // we have an error in the encoding...
                            // s--;
                        }
                    }
                    mid[i] = s[i];
                }
                // now we just have to convert the hex std::string to an char...
                if (ok) {
                    s += 2;
                    int m = hexmap[mid[0]];
                    m <<= 4;
                    m |= hexmap[mid[1]];
                    *(result++) = (char)m;
                }
            }
            else {
                if (*s != '\0')
                    *(result++) = *(s++);
            }
        }

        return finalresult;
    }

  public:
    void clear()
    {
        headers.clear();
        data.clear();
    }

    std::vector<char> GetData() const { return data; }

    void SetData(std::vector<char> &x) { data = x; }

    void SetData(const char *a, size_t ss = -1)
    {
        if (ss == -1)
            ss = strlen(a);
        else {
            std::vector<char> d(ss);
            d.assign(a, a + ss);
            SetData(d);
            return;
        }

        std::string j = a;
        Trim(j);
        if (j.empty())
            return;
        data.assign(j.begin(), j.end());
    }

    void DecodeData(std::vector<char> &d)
    {
        auto a2 = hval("Content-Transfer-Encoding");
        if (_stricmp(a2.c_str(), "base64") == 0) {
            DWORD dw = 0;
            CryptStringToBinaryA(data.data(), (DWORD)data.size(),
                                 CRYPT_STRING_BASE64, 0, &dw, 0, 0);
            d.resize(dw);
            CryptStringToBinaryA(data.data(), (DWORD)data.size(),
                                 CRYPT_STRING_BASE64, (BYTE *)d.data(), &dw, 0,
                                 0);
            return;
        }
        if (_stricmp(a2.c_str(), "quoted-printable") == 0) {
            std::vector<char> nd(data.size() + 10);
            strcpy_s(nd.data(), nd.size(), data.data());
            char *ce = QPDecode(nd.data());
            d.resize(strlen(ce) + 1);
            strcpy_s(d.data(), d.size(), ce);
            free(ce);
            return;
        }
        d = data;
    }

    MIME2::HEADER httphdr() const
    {
        for (auto &a : headers) {
            if (a.IsHTTP())
                return a;
        }
        MIME2::HEADER me;
        return me;
    }

    /*			string Content()  const
                                    {
                                    std::string a;
                                    auto d2 = data;
                                    d2.resize(d2.size() + 1);
                                    a = d2.data();
                                    d2.resize(d2.size() - 1);
                                    return a;
                                    }
    */

    std::string hval(const char *left) const
    {
        for (auto &a : headers) {
            if (_strcmpi(a.Left().c_str(), left) == 0)
                return a.Right();
        }
        return "";
    }
    std::string hval(const char *left, const char *rpart) const
    {
        for (auto &a : headers) {
            if (_strcmpi(a.Left().c_str(), left) == 0)
                return a.Right(rpart);
        }
        return "";
    }

    HEADER &AddHTTPHeader(const char *l)
    {
        HEADER h;
        h.Parse(l, true);
        headers.insert(headers.begin(), h);
        return headers[0];
    }

    HEADER &operator[](const char *l)
    {
        for (auto &h : headers) {
            if (_stricmp(h.Left().c_str(), l) == 0)
                return h;
        }
        HEADER h;
        std::string e = l;
        e += ": ";
        h.Parse(e.c_str());
        headers.push_back(h);
        return headers[headers.size() - 1];
    }

    MIMEERR Parse(const char *f, bool CanHTTP = false, size_t ss = -1)
    {
        if (!f)
            return MIMEERR::INVALID;

        // Until \r\n\r\n
        const char *a2 = strstr(f, "\r\n\r\n");
        int jd = 4;
        const char *a21 = strstr(f, "\n\n");
        if (!a2 && !a21) {
            // No headers....
            SetData(f);
            return MIMEERR::OK;
        }
        if (a21 && !a2) {
            a2 = a21;
            jd = 2;
        }
        else if (!a21 && a2) {
            jd = 4;
        }
        else if (a21 < a2) {
            a2 = a21;
            jd = 2;
        }

        std::vector<char> hdrs;
        hdrs.resize(a2 - f + 10);
        strncpy_s(hdrs.data(), hdrs.size(), f, a2 - f);

        // Parse them
        std::vector<std::string> hd;
        Split(hdrs.data(), '\n', hd);
        for (auto &a : hd) {
            HEADER h;
            if ((a[0] == ' ' || a[0] == '\t') && headers.size()) {
                // Join with previous
                auto &ph = headers[headers.size() - 1];
                ph.rights().getstrings().push_back(Trim(a));
                continue;
            }
            Trim(a);
            auto err = h.Parse(a.c_str(), CanHTTP);
            if (err != MIMEERR::OK)
                return err;
            headers.push_back(h);
        }

        if (ss == -1)
            SetData(a2 + jd);
        else
            SetData(a2 + jd, ss - (a2 - f) - jd);
        return MIMEERR::OK;
    }

    /*			string Serialize() const
                                    {
                                    std::string r = SerializeHeaders();
                                    if (r.length())
                                            r += "\r\n";
                                    r += Content();
                                    return r;
                                    }
    */
    std::vector<char> SerializeToVector() const
    {
        std::string r = SerializeHeaders();
        if (r.length())
            r += "\r\n";
        std::vector<char> x;
        x.resize(r.length());
        memcpy(x.data(), r.c_str(), r.length());
        auto os = x.size();
        x.resize(x.size() + data.size());
        memcpy(x.data() + os, data.data(), data.size());
        return x;
    }

    std::string SerializeHeaders() const
    {
        std::string r;
        for (auto &h : headers) {
            r += h.Serialize();
            r += "\r\n";
        }
        return r;
    }
};

class CONTENTBUILDER {
    std::vector<std::vector<char>> parts;
    std::string Boundary;

  public:
    CONTENTBUILDER()
    {
        UUID u = {0};
        CoCreateGuid(&u);
        //* test :)
        TCHAR str[1000];
        StringFromGUID2(u, str, 1000);
        char star[1000];
        WideCharToMultiByte(CP_UTF8, 0, str, -1, star, 1000, 0, 0);
        Boundary = star;
    }

    void clear() { parts.clear(); }

    void Add(char *Data)
    {
        std::vector<char> x(strlen(Data));
        memcpy(x.data(), Data, strlen(Data));
        parts.push_back(x);
    }

    void Add(CONTENT &c)
    {
        auto h1 = c.SerializeToVector();
        parts.push_back(h1);
    }

    std::vector<std::vector<char>> &GetParts() { return parts; }

    void Build(CONTENT &c, const char *Sign = 0)
    {
        c.clear();
        c["MIME-Version"] = "1.0";
        std::string a = "multipart/mixed";
        if (Sign)
            a = Sign;
        a += "; boundary=\"";
        a += Boundary;
        a += "\"";
        c["Content-Type"] = a.c_str();

        std::vector<char> d;
        for (auto &aa : parts) {
            std::string j = "--";
            j += Boundary;
            j += "\r\n";

            std::vector<char> jj(j.length() + aa.size() + 2);
            memcpy(jj.data(), j.c_str(), j.length());
            memcpy(jj.data() + j.length(), aa.data(), aa.size());
            memcpy(jj.data() + j.length() + aa.size(), "\r\n", 2);
            auto es = d.size();
            d.resize(es + jj.size());
            memcpy(d.data() + es, jj.data(), jj.size());
        }

        auto es = d.size();
        d.resize(es + 2 + Boundary.size() + 4);
        memcpy(d.data() + es, "--", 2);
        memcpy(d.data() + es + 2, Boundary.c_str(), Boundary.size());
        memcpy(d.data() + es + 2 + Boundary.size(), "--\r\n", 4);

        c.SetData(d);
    }
};

inline void BuildZ(CONTENT &c1, CONTENT &c2, CONTENT &co, const char *s)
{
    CONTENTBUILDER cb2;
    cb2.Add(c1);
    cb2.Add(c2);
    cb2.Build(co, s);
}
inline MIMEERR ParseMultipleContent2(const char *d, size_t sz, const char *del,
                                     std::vector<CONTENT> &Result)
{
    if (!d || !del)
        return MIMEERR::INVALID;

    std::string dx = "--";
    dx += del;
    std::vector<std::vector<char>> r;

    BinarySplit(d, sz, dx.c_str(), r);

    if (r.size() < 2)
        return MIMEERR::INVALID;

    std::string delj = "--";
    delj += del;
    // First, check if [0] starts with it
    if (r[0].size() == 0 ||
        strncmp(r[0].data(), delj.c_str(), delj.length()) != 0)
        r.erase(r.begin());

    // Check last if it starts with --
    if (strncmp(r[r.size() - 1].data(), "--", 2) == 0)
        r.erase(r.end() - 1);
    else
        return MIMEERR::INVALID;

    for (auto &a : r) {
        CONTENT c;
        Trim(a, 2);
        TrimOnce(a);
        auto ra = a;
        ra.resize(ra.size() + 1);
        auto err = c.Parse(ra.data(), 0, ra.size() - 1);
        if (err != MIMEERR::OK)
            return err;

        Result.push_back(c);
    }

    return MIMEERR::OK;
}

} // namespace MIME2
