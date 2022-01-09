

# API Gateways em ambiente SpringCloud



Tabalho que visa criar um API para autenticação com Spring Boot e JWT, e apresentar o detalhamento da construção e dos temas transversais, na primeira fase como :

​		Spring Boot -  JWT - DTO - Lombok - Beans - MVC - abstração 

```
O projeto é criado a partir do material do curso : "API Gateways em ambiente Azure SpringCloud", da Dio , com o Rodrigo Tavares
```



## Premissas  

- Conhecimento básico de

  - Java

  - IDE

  - Spring Boot 



## Conceitos Gerais 

**Autenticação** : Validar entrada na aplicação e acesso a recursos

Técnica de autenticação : **JWT** - Jason Web Tokens ( chave de identificação a ser utilizada pelas APIs )

JSON - Evolução do XML - comunicação na web - transforma objetos do javascrit em um protocolo de transferê ncia pela internet 

Implementar ( não vou criar os componentes que fazem algo, é criado a forma de como deve ser feito . digo que deve ter métodos , dever uma entrada A ou B . ë criado um padrão a ser implementado . 

O JWT apresenta um padrão , o qual implementamos : Auth0 - pega toda JWT e implementa o token. 

```
Comparação : Drive de impressora  . O SO precisa saber como enviar dados para a impressora, independente de qual impressora voce tem , ai o drive recebe os dados e trata da forma que a impressora entenda.  
```



## Criar projeto

1. Acessar o site do Spring Boot :https://start.spring.io/
2. Criar pacote Spring : Ultima versão Spring / Java / Maven ( gerenciador de dependencias Java )
   1. Definir grupo : convenção é a URL de sua empresa escrita ao contrario ( br.com.suaempresa) 
   2. Definir artefato : springboot-jwt 
   3. Nome : Spring Boot JWT ( nome deste trabalho - pode ser em maiúscula  )
   4. Package name :  br.com.suaempresa.jwt
   5. Packaging : .jar
   6. Java :  11 ( ou a ultima versão LTS , não utillziar em ambiente de produção versões FR 
   7. Adicionar dependencias 
      1. Spring WEB  ( será usado o JPA)
      2. Spring Security
   8. Gerar o arquivo Spring
   9. Descompactar e colocar o diretório de trabalho  



```
Nota : A JPA define um meio de mapeamento objeto-relacional ( Banco de Dados ) para objetos Java simples e comuns, denominados beans de entidade.JPA é uma coleção de classes e métodos voltados para armazenar persistentemente as vastas quantidades de dados em um banco de dados
```



## Estrutura Inicial 

1. Abrir no Intellij

2. As dependecias estão registradas no arquivo pom.xml

3. O spring boot  ja entrega uma classe main, dentro da aplicação ( container embebed )

   ![Screen Shot 2022-01-07 at 17.35.19](https://tva1.sinaimg.cn/large/008i3skNgy1gy5rw01bvrj307d02ja9x.jpg)

4. Ao rodar a aplicação, ela inicia, e o servido ajusta para a porta 8080 

   ```
   nota : portas acima da 1024 pode ser liberadas por usuário padrão , a baixo disto somnete administrador pode liberar 
   ```

   

5. Acesse  no browse : http://localhost:8080/login , para ver a aplicação "no ar"  

6. Alterando a ASCII Art. Criar na pasta *resources* um arquivo banner.txt . O que for colocado ali , sera apresentado no lugar do "logo"do spring . 


   ![Screen Shot 2022-01-07 at 18.03.47](https://tva1.sinaimg.cn/large/008i3skNgy1gy5spl0jypj306y04pt8p.jpg)

   ![Screen Shot 2022-01-07 at 18.03.52](https://tva1.sinaimg.cn/large/008i3skNgy1gy5sq7020vj30cb04074e.jpg)

   

   

   ## Autenticação - Primeiros Passos 


```
Nota : os componentes do Java são chamados de "bean" em referencias aos grãos de café 
```

```
DTO - Data Transfer Object ou simplesmente Transfer Object é um padrão de projetos bastante usado em Java para o transporte de dados entre diferentes componentes de um sistema, diferentes instâncias ou processos de um sistema distribuído ou diferentes sistemas via serialização.
```

1. Será usado um DTO com o usuário que fara autenticação 

   Estrutura -> package *Data* -> classe *Userdata* 

2. Implementer Serializable na classe UserData 

   ```
   Serializable : O java gravará na máquina local os dados de autenticação, se ficar off-line , ao voltar se autentica novamente . A serialização em Java é o processo no qual a instância de um objeto é transformada em uma sequência de bytes e é útil quando precisamos enviar objetos pela rede, salvar no disco, ou comunicar de uma JVM com outra.
   ```

3. Por conveção , criar getters e setters . Atualmente é um padrão obrigatório em java , mesmo que voce não use . Para facilitar a codificação e manter o codigo mais limpo , sera usado o Lombok , que cria os getters e setters em tempo de compilação . 

   1. Inserir chamada ao  lombok, no arquivo pom.xml , colocar como ultima dependencia 

   2. para pegar as linhas a serrem inseriddas , procurar no google : Lombok maven

   3. ou ir no site : https://projectlombok.org/mavenrepo/

   4. Ajusta para ultima versão e tirar a linha escopo 

      ```
      <dependency>
         <groupId>org.projectlombok</groupId>
         <artifactId>lombok</artifactId>
         <version>1.18.12</version>
      </dependency>
      ```

   5. No lado direito do Intellij , em Maven , atualizar as dependencias 

      ![Screen Shot 2022-01-08 at 10.17.14](https://tva1.sinaimg.cn/large/008i3skNgy1gy6kuhz9tnj303s04at8l.jpg)

      

      ![Screen Shot 2022-01-08 at 10.18.00](https://tva1.sinaimg.cn/large/008i3skNgy1gy6kv45mk5j309803p0su.jpg)
      

4. Inserir anotações, para que o compilador entenda que a classe precisa ser manipulada pelo Lombok, e criar em tempo de compilação os getters, setters e um construtor sem argumentos. 

5. ```
   package com.fj.springbootjwt.data;
   
   import lombok.Getter;
   import lombok.NoArgsConstructor;
   import lombok.Setter;
   
   import java.io.Serializable;
   
   @Getter @Setter @NoArgsConstructor
   public class UserData implements Serializable {
   
       String userName;
       String password;
   }
   ```

6. Configurar Intellij para tratar o lombok . Outras ides tem processos parecidos.
     -> Inserir plug in Lombok

    -> habilitar : Preferences /  Build Execution Deployment / Compiler / Annotations Processor / Enable annotations Processing

   

​      

      ## Código para processar requisições  



**Criar um serviço para validar o usuário  .**

1. Criar pacote service e a classe UsersDetailsServiceImpl

2. Implementar a classe java *UsersDetailsService*, esta classe tem *loaduserbayname* , quem implementa ela sabe que ela carrega o usuário , mas não sabe como. 

3. Implantar metodo de pesquisa . Dentro deste metodo , não importa onde estou buscando o usuário : Bando de dados , arquivo texto , etc  ( conceito de abstração )

4. Criar metodo de findUser , que neste projeto sera a crição do proprio usuário / senha 

5. Para encriptografar a senha , sera inserido um bean , na  classe main , que fica disponível para toda a aplicação

   ```
   @SpringBootApplication
   public class SpringbootjwtApplication {
   
      public static void main(String[] args) {
         SpringApplication.run(SpringbootjwtApplication.class, args);
      }
   
      @Bean
      public BCryptPasswordEncoder bCryptPasswordEncoder(){
         return new BCryptPasswordEncoder();
      }
   
   }
   ```

   

6. É necesario declarar o bean na classe em que quer utilizar . 

6. E é necessário fazer a anotação Spring *@Service* para ser um serviço válido e o spring possa ve-lo.
   Ficando o código  assim . 
   
   ```
   @Service
   public class UserDetailsServiceImpl implements UserDetailsService {
   
       private final BCryptPasswordEncoder bCryptPasswordEncoder;
   
       // por ser "final" precisa ser inicializado
       public UserDetailsServiceImpl(BCryptPasswordEncoder bCryptPasswordEncoder) {
           this.bCryptPasswordEncoder = bCryptPasswordEncoder;
       }
   
       @Override
       public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
       
           UserData user = findUser( username);
           if ( user == null ){
               throw new UsernameNotFoundException( username);
           }
   
           return new User( user.getUserName(), user.getPassword(), Collections.emptyList());
       }
   
       // este metodo poderia ser construido para ir buscar o usuário
       // em qualuer lugar ( banco de dados, arquivo texto , etc ) 
       private UserData findUser(String username) {
   
           UserData user = new UserData();
           user.setUserName("admin");
           user.setPassword( bCryptPasswordEncoder.encode("nimda"));
   
           return user;
       }
       
   }
   ```

   ```
   Nota : Anotações do Spring Framework
   Em aplicações é comum termos camadas distintas, como acesso a dados, serviço, negócios.
   Em cada camada podem existir vários beans. Para detectá-los automaticamente, o Spring usa anotações de verificação e em seguida, registra cada bean no ApplicationContext.
   ```
   
   
   
8. Criar uma lista de usuários. Inserido ao final da classe UserDetailsServiceImpl.

```
public List<UserData> ListUsers() {
    ArrayList<UserData> lst = new ArrayList<>();
    lst.add(findUser("admin"));
    return lst;
}
```



**Desenvolvendo o pacote Security**

1. Criar pacote security. dentro da arquitetura MVC - Model View Controller, que separa a regra de negócio no back-end do que o usuário ve ( front-end) 

2. Criar 3 classes : 
   1. Uma que vai autenticar - como vai autenticar -> Constrains/Constants
   
      ```
      public class SecurityConstants {
          // chave interna so vista na sua aplicação
          // sem ela não sera possivel decriptografa a senha
          // mesma senha / user em aplicações diferentes
          // gera criptografias diferentes
          public static final String SECRET = "SecretKeyToGenJWTs";
      
          // tempo de duração da chave , em milisegundos
          public static final long EXPIRATION_TIME = 864_000_000;  // 10 DIAS
      
          // prefixo que indentifica o tipo de token sendo criado
          public static final String TOKEN_PREFIX = "Bearer ";
      
          // cabeçalho onde estará o token
          public static final String HEADER_STRING = "Authorization";
      
          // url onde para entrar não sera solicitada senha
          public static final String SIGN_UP_URL =  "/login";
          public static final String STATUS_URL = "/status";
      
      }
      ```

**Desenvolvendo o pacote Controller** ( APIs ) 

1. StatusController - Ao criar uma API precisa avisar ao Spring que a classe sera a API , a partir da anotação *@RestController*

   ```
   @RestController
   public class StatusController {
   
       // se a aplicação estiver no ar
       // aparece a mensagem quando entra na URL
       @RequestMapping("/status")
       public String viewStatus(){
           return "On Line";
       }
   
   }
   ```

   
   
2. UserController 

```
import java.util.List;

@RestController
public class UserController {

    // declarando o serviço
    private final UserDetailsServiceImpl userDetailsService;

    public UserController(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @RequestMapping("/all-users")
    public List<UserData> listAllUsers() {
        // userDetailsService é um serviço
        // precisa ser declarado
        return userDetailsService.listUsers();
    }

}
```



**Informar ao Spring que não é para usar a tela de login , o controle é meu**

1. Criar em Security a classe WebSecurity
   a anotação @EnableWebSecurity informa que eu estou controlando a segunça no Spring desta aplicação . ver comentários no código para mais detalhes . 

   ```
   @EnableWebSecurity
   public class WebSecurity extends WebSecurityConfigurerAdapter {
   
       // declarando 2 serviços
       private final UserDetailsServiceImpl userDetailsService;
       private final BCryptPasswordEncoder bCryptPasswordEncoder;
   
       // criar construtor dos serviços
       public WebSecurity(UserDetailsServiceImpl userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
           this.userDetailsService = userDetailsService;
           this.bCryptPasswordEncoder = bCryptPasswordEncoder;
       }
   
       // fazer a configuração
       // informar ao Spring qual segurança que quero na aplicação
       // desabilitado cors - posso chamar meu serviço de qualquer URL
       // cors força que as apis acessem todas as paginas somente que estejam dentro
       // da URL  principal (  www.minhapagina.com )
       @Override
       protected void configure(HttpSecurity http) throws Exception {
           http.cors().and().csrf().disable().authorizeRequests()
                   // permitir  GET da STATUS_URL
                   .antMatchers(HttpMethod.GET, SecurityConstants.STATUS_URL)
                   .permitAll()
                   // permitir POST da SIGN_UP_URL
                   .antMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL)
                   .permitAll()
                   // qualuer outra requisição precisa estar autenticado
                   .anyRequest().authenticated();
       }
   
       // encripta e desencripta a password
       // pega os detalhes do usuário passado pelo serviço
       @Override
       public void configure(AuthenticationManagerBuilder auth) throws Exception {
           auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
       }
   
        // avisando de que qualquer url que fizer a requisição , vou aceitar
       // de qualquer servidor que vir a requisção da API será aceita
         @Bean
         CorsConfigurationSource corsConfigurationSource() {
           final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
           source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
           return source;
         }
   }
   ```



**Criar código de Login**

```
<< Conceito geral de segurança da Informação >> 
Identificação : me apresentao sou o sistema X 
Autenticação :  Apresento elementos que provem que sou quem digo ser (senha/cracha, etc ) 
Autorização : verifica se o elemento apresentado é verdadeiro e libera os acessos a que tem direito 

```



1. Criar, em Controller , a  classe AuthController 

```
@RestController
public class AuthController {

    // pegar o login e encriptar
    // não é necessário instanciar pois criamos um Bean na classe main
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // criar o construto do encriptador
    public AuthController(BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    // criar método do tipo POST em / login

    @PostMapping("/login")
    // recebo de UserData -  quem faz a requisção passa esta informação
    public void login(@RequestBody UserData user) {
        // a senha é fornecida em texto plano e precisa ser encriptada
        // para que isto ocorra é necessário criar as classe que
        // façam a encriptação e a validação da senha 
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
    }

}
```

2. ciar a classe J*WTAuthenticationFilter* que vai autenticar o usuario - no pacote Security

   1. precisa colocar no POM a dependencia do Auth0, depois do Lombok.

      	<dependency>
      		<groupId>com.auth0</groupId>
      		<artifactId>java-jwt</artifactId>
      		<version>3.13.0</version>
      	</dependency>

      

   2. Código ( ver comentários para detalhes )

      ```
      Nota : Filtro em Java são interceptadores . Pegam a requisição e efetuam uso dela para algo
      ```

      ```
      // criando um filtro
      public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
      
      // a requisição recebe o AuthenticationManager -------------------------------------
          // é do security do SpringBoot
          private final AuthenticationManager authenticationManager;
      
          public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
              this.authenticationManager = authenticationManager;
          }
      // -----------------------------------------------------------------------------
      
          // implementado métodos que vem da classe que extendemos
          // UsernamePasswordAuthenticationFilter
          // localizar o autenticador
          // UserData - dados do usuário que estará dentro do token
          @Override
          public Authentication attemptAuthentication(HttpServletRequest req,
                                                      HttpServletResponse res) throws AuthenticationException {
              try {
                  UserData creds = new ObjectMapper()
                          .readValue(req.getInputStream(), UserData.class);
      
                  return authenticationManager.authenticate(
                          new UsernamePasswordAuthenticationToken(
                                  // pedir para autenticar
                                  creds.getUserName(),
                                  creds.getPassword(),
                                  new ArrayList<>())
                  );
              } catch (IOException e) {
                  throw new RuntimeException(e);
              }
          }
      
          // se a autenticar for bem sucedida
          // gera o token utilzando  Auth0
          // coloca no header do retorno da requisição
          // coloca no token :
          // os dados do usuário
          // ( poderia colcar qualquer coisa necessaria , por exemplo o saldo do correntista
          // o prozo de validade
          // qual algoritmo utilizado
          @Override
          protected void successfulAuthentication(HttpServletRequest req,
                                                  HttpServletResponse res,
                                                  FilterChain chain,
                                                  Authentication auth) throws IOException, ServletException {
      
              String token = JWT.create()
                      .withSubject(((User) auth.getPrincipal()).getUsername())
                      .withExpiresAt(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
                      .sign(Algorithm.HMAC512(SecurityConstants.SECRET.getBytes()));
      
              res.addHeader(SecurityConstants.HEADER_STRING, SecurityConstants.TOKEN_PREFIX + token);
          }
      }
      ```

      

   3. Precisa colocar JWTAuthenticationFilter no WebSecurity 

      
      
      protected void configure(HttpSecurity http) throws Exception {
              http.cors().and().csrf().disable().authorizeRequests()
                      // permitir  GET da STATUS_URL
                      .antMatchers(HttpMethod.GET, SecurityConstants.STATUS_URL)
                      .permitAll()
                      // permitir POST da SIGN_UP_URL
                      .antMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL)
                      .permitAll()
                      // qualuer outra requisição precisa estar autenticado
                      .anyRequest().authenticated()
                      .and()
                      // filtro que faz a autenticação 
                      .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                      // não precisa guardar a sessão 
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
          }
      
      
      
   3. Criar  JWTAuthorizationFilter noSecurity - interpretar a requisição 
   
      ```
      public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
      
          public JWTAuthorizationFilter(AuthenticationManager authManager) {
              super(authManager);
          }
      
          @Override
          protected void doFilterInternal(HttpServletRequest req,
                                          HttpServletResponse res,
                                          FilterChain chain) throws IOException, ServletException {
      
              String header = req.getHeader(SecurityConstants.HEADER_STRING);
              // verificar se a sinformações recebidas estão certas
              if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
                  chain.doFilter(req, res);
                  return;
              }
      
              UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
      
              SecurityContextHolder.getContext().setAuthentication(authentication);
              chain.doFilter(req, res);
          }
      
          private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
              String token = request.getHeader(SecurityConstants.HEADER_STRING);
              if (token == null) {
                  return null;
              }
      
              // Parse the token.
              // converter o token em uma string de usuário
              String user = JWT.require(Algorithm.HMAC512(SecurityConstants.SECRET.getBytes()))
                      .build()
                      .verify(token.replace(SecurityConstants.TOKEN_PREFIX, ""))
                      .getSubject();
      
              if (user != null) {
                  // se usuário nao nulo , vai usar o usuário
                  // as credencias não são salvas no token
                  return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
              }
      
              return null;
          }
      }
      ```
      
   3. Precisa colocar JWTAuthorizationFilter no WebSecurity 
   
      ```
      protected void configure(HttpSecurity http) throws Exception {
              http.cors().and().csrf().disable().authorizeRequests()
                      // permitir  GET da STATUS_URL
                      .antMatchers(HttpMethod.GET, SecurityConstants.STATUS_URL)
                      .permitAll()
                      // permitir POST da SIGN_UP_URL
                      .antMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL)
                      .permitAll()
                      // qualuer outra requisição precisa estar autenticado
                      .anyRequest().authenticated()
                      .and()
                      // filtro que faz a autenticação - gera o token
                      .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                      // filtro que faz a autorização - le o token 
                      .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                      // não precisa guardar a sessão                     .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
          }
      ```









