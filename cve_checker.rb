#! /usr/bin/env ruby

# TODO
# - Send an email to a particular email address with all the new vulnerabilities found. All the vulnerabilities should be sent in the same email
# - Update it's storage of the last vulnerability found so that it doesn't email us again until a new vulnerability is published

require 'nokogiri'
require 'open-uri'
require 'yaml'
require 'mail'

cve_base_uri = 'https://www.cvedetails.com'

gmail_address = 'cole.thompson@gmail.com'
secrets = YAML.load_file "secrets.yml"
gmail_password = secrets['gmail_password']

product_name = "OpenSSL"
search_uri = 'https://www.cvedetails.com/vulnerability-list/vendor_id-217/product_id-383/Openssl-Openssl.html'

search_page = Nokogiri::HTML(open(search_uri))
cve_search_results = search_page.css('.searchresults tr.srrowns')

latest_cve_info = YAML.load_file "latest_cve.yml"

if cve_search_results.length > 0
  latest_cve_result = cve_search_results[0]
  if latest_cve_result.css('td')[1].text != latest_cve_info[product_name][:cve_id]
    cve_search_results.each do |cve_result|
      cve_id = cve_result.css('td')[1].text
      cve_href = cve_result.css('td a')[1]['href']

      if cve_id == latest_cve_info[product_name][:cve_id]
        break
      end

      puts cve_id, cve_base_uri + cve_href
    end

    latest_cve_info = {}
    latest_cve_info[product_name] = {}
    latest_cve_info[product_name][:cve_id] = latest_cve_result.css('td')[1].text
    latest_cve_info[product_name][:last_time_run] = Time.now.utc
    File.open("latest_cve.yml", "w") { |file| file.write YAML.dump latest_cve_info }

    smtp_options = { :address              => "smtp.gmail.com",
                     :port                 => 587,
                     :user_name            => gmail_address,
                     :password             => gmail_password,
                     :authentication       => 'plain',
                     :enable_starttls_auto => true  }
    Mail.defaults do
      delivery_method :smtp, smtp_options
    end
    Mail.deliver do
      to      "cole.thompson@gmail.com"
      from    "cole.thompson@gmail.com"
      subject "New CVEs found"
      body    "test"
    end
  end
end

