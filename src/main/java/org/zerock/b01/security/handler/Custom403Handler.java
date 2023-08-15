package org.zerock.b01.security.handler;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

@Log4j2
public class Custom403Handler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        log.info("----ACCESS DENIED----");
        response.setStatus(HttpStatus.FORBIDDEN.value());

        //json 요청이였는지 확인
        String contentType = request.getHeader("Content-type");
        boolean jsonRequest = contentType.startsWith("application/json");

        log.info("isJSON : "+ jsonRequest);

        //일반 request
        if(!jsonRequest){
            response.sendRedirect("/member/login?error=ACCESS_DENIED");
        }
    }
}
