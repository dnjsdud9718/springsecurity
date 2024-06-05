package io.security.springsecurity;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/anonymous")
    public String anonymous() {
        return "anonymous";
    }

    @GetMapping("/authentication")
    public String authentication(Authentication authentication) {
        System.out.println(authentication == null);

        // 익명 객체 참조할 수 없음 -> null이 들어온다. 잘못된 예제를 표현하는 것 -> @CurrentSecurityContext 사용해야 한다.
        if (authentication instanceof AnonymousAuthenticationToken) {
            return "anonymous";
        } else {
            return "non anonymous";
        }
    }

    /*
     * 익명 요청에서 Authentication을 얻고 싶으면 @CurrentSecurityContext를 사용
     * -> CurrentSecurityContextArgumentResolver에서 요청을 가로채어 처리한다.
     * -> SecurityContext를 반환
     */
    @GetMapping("/anonymousContext")
    public String anonymousContext(@CurrentSecurityContext SecurityContext context) {
        // 익명 객체 참조 가능 -> 접근 가능하다.
//        Authentication auth = context.getAuthentication();
        return context.getAuthentication().getName();
    }

    @GetMapping("/logoutSuccess")
    public String logoutSuccess() {
        return "logoutSuccess";
    }
}
