#include <cstdlib>
#include <fstream>
#include <iostream>

#include "robots.h"
#include "absl/strings/string_view.h"

#include "FuzzedDataProvider.h"

googlebot::RobotsMatcher matcher{};

bool IsUserAgentAllowed(const absl::string_view &robots_txt, const std::string& user_agent, const std::string& url) {
    return matcher.OneAgentAllowedByRobots(robots_txt, user_agent, url);
}
class RobotsStatsReporter : public googlebot::RobotsParseHandler {
public:
    void HandleRobotsStart() override {
        last_line_seen_ = 0;
        valid_directives_ = 0;
        unknown_directives_ = 0;
        sitemap_.clear();
    }
    void HandleRobotsEnd() override {}

    void HandleUserAgent(int line_num, absl::string_view value) override {
        Digest(line_num);
    }
    void HandleAllow(int line_num, absl::string_view value) override {
        Digest(line_num);
    }
    void HandleDisallow(int line_num, absl::string_view value) override {
        Digest(line_num);
    }

    void HandleSitemap(int line_num, absl::string_view value) override {
        Digest(line_num);
        sitemap_.append(value.data(), value.length());
    }

    // Any other unrecognized name/v pairs.
    void HandleUnknownAction(int line_num, absl::string_view action,
                             absl::string_view value) override {
        last_line_seen_ = line_num;
        unknown_directives_++;
    }

    int last_line_seen() const { return last_line_seen_; }

    // All directives found, including unknown.
    int valid_directives() const { return valid_directives_; }

    // Number of unknown directives.
    int unknown_directives() const { return unknown_directives_; }

    // Parsed sitemap line.
    std::string sitemap() const { return sitemap_; }

private:
    void Digest(int line_num) {
        last_line_seen_ = line_num;
        valid_directives_++;
    }

    int last_line_seen_ = 0;
    int valid_directives_ = 0;
    int unknown_directives_ = 0;
    std::string sitemap_;
};


extern "C" __attribute__((unused)) int LLVMFuzzerTestOneInput(const uint8_t *fuzz_data, size_t size) {
    FuzzedDataProvider fdp(fuzz_data, size);

    const absl::string_view robots_txt{fdp.ConsumeRandomLengthString()};
    const auto user_agent = fdp.ConsumeRandomLengthString();
    const auto url = fdp.ConsumeRemainingBytesAsString();

    IsUserAgentAllowed(robots_txt, user_agent, url);
    RobotsStatsReporter reporter;
    googlebot::ParseRobotsTxt(robots_txt, &reporter);
    return 0;
}